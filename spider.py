import aiohttp
import asyncio
import re
import json
import argparse
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse
from typing import List, Dict
from SecretFinder import SecretFinder



class AsyncWebCrawler:
    def __init__(self, start_url, max_depth):
        self.start_url = start_url
        self.domain = '{uri.netloc}'.format(uri=urlparse(start_url))
        self.base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(start_url))
        self.max_depth = max_depth  
        self.data = {
            "emails": set(),
            "links": set(),
            "comments": set(),
            "external_link": set(),
            "js_files": set(),
            "possible_endpoints":set(),
            "images": set(),
            "sensitive_data": dict(),
            "documents": set()
            
        }
        self.email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        self.endpoint_pattern = r'https?://[\w\-\.]+(?:/[\w\-/]*)?'
        self.api_pattern = r'\/[a-zA-Z0-9_\-]+'
        self.document_pattern = r'https?://[\w\-\.]+(?:/[\w\-/]*\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|csv))'
    def extract_emails(self, text):
        return set(re.findall(self.email_pattern, text))

    def extract_endpoints(self, text):
        urls =  set(re.findall(self.endpoint_pattern, text))
        possible_endpoints = set(re.findall(self.api_pattern, text))
        return urls,possible_endpoints
    
    async def find_images(self, images):
        for img in images:
            img_url = img.get('src')
            img_url = urljoin(self.base_url, img_url)
            self.data['images'].add(img_url)

    async def parse_js(self, session, url):
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    js_content = await response.text()
                    urls,_ = self.extract_endpoints(js_content)
                    for url in urls:
                        if self.domain in url:
                            self.data['links'].add(url)
                        else:
                            self.data['external_link'].add(url)
                    secret_finder = SecretFinder(js_content)
                    sensitive_data = secret_finder.find_sensitive_data()
                    for key, values in sensitive_data.items():
                        if key not in self.data['sensitive_data']:
                            self.data['sensitive_data'][key]=set()
                        self.data['sensitive_data'][key].update(values)

        except Exception as e:
            print(f"Error parsing JS file {url}: {e}")

    async def crawl_page(self, session, url, depth):
        """Crawls a single page, extracting data and following links."""
        if depth > self.max_depth:
            return
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    soup = BeautifulSoup(await response.text(), 'html.parser')
                    
                    # Find Emails
                    self.data['emails'].update(self.extract_emails(await response.text()))
                    
                    # Find comments
                    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
                    self.data['comments'].update([c.strip() for c in comments if c.strip()])
                    
                    # Find images
                    images = soup.find_all('img')
                    await self.find_images(images)
                    
                    
                    tasks = []
                    for link in soup.find_all('a', href=True):
                        full_link = urljoin(self.base_url, link['href'])
                        
                        if full_link not in self.data['links'] and self.domain in '{uri.netloc}'.format(uri=urlparse(full_link)) and "http" in full_link:
                            match =re.match(self.document_pattern,full_link)
                            if match:
                                self.data['documents'].add(match[0])
                            else:
                                self.data['links'].add(full_link)
                                tasks.append(self.crawl_page(session, full_link, depth + 1))  
                    
                    # Parse JS files
                    for script in soup.find_all('script', src=True):
                        js_url = urljoin(self.base_url, script['src'])
                        if js_url not in self.data['js_files']:
                            self.data['js_files'].add(js_url)
                            tasks.append(self.parse_js(session, js_url))
                    
                    await asyncio.gather(*tasks)
        except Exception as e:
            print(f"Error crawling {url}: {e}")

    async def start_crawling(self):
        """Starts the crawling process from the start URL."""
        async with aiohttp.ClientSession() as session:
            await self.crawl_page(session, self.start_url, 0)
            self.save_results()
            
    def save_results(self):
        """Saves the collected data into a JSON file."""
        json_data = {
            key: list(value) if isinstance(value, set) else value
            for key, value in self.data.items()
        }
        if isinstance(json_data['sensitive_data'], dict):
            json_data['sensitive_data'] = {
                key: list(values) for key, values in json_data['sensitive_data'].items()
            }
        with open('recon_output.json', 'w') as json_file:
            json.dump(json_data, json_file, indent=4)

        print("Results saved to recon_output.json")
    


def main():
    parser = argparse.ArgumentParser(description="Async Web Crawler for Recon")
    parser.add_argument('-u', '--url', required=True, help='The start URL for crawling.')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('-o', '--output', default='recon_output.json', help='Output JSON file (default: recon_output.json)')

    args = parser.parse_args()

    crawler = AsyncWebCrawler(args.url, args.depth)
    try:
        asyncio.run(crawler.start_crawling())
    except:
        crawler.save_results()
    print(f"Crawling complete! Results saved to {args.output}")


if __name__ == "__main__":
    main()
