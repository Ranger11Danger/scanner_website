from bs4 import BeautifulSoup
import requests

def get_data(cve):
    data = requests.get(f'https://www.tenable.com/cve/{cve}')
    soup = BeautifulSoup(data.text, 'html.parser')
    description = soup.find(text="Description").find_next('p').text
    solution = soup.find(text="References").find_next('p').text
    score = soup.findAll(text="CVSS v3")[2].find_next('span').text
    return(description,solution,score)

description, solution, score = get_data('CVE-2019-7358')
print(type(score))