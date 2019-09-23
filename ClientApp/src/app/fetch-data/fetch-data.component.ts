import { Component } from '@angular/core';
import { OpisenseService, OpisenseSource, OpisenseData } from './opisense.service';

@Component({
  selector: 'app-fetch-data',
  templateUrl: './fetch-data.component.html',
  providers: [OpisenseService]
})
export class FetchDataComponent {
  public sources: OpisenseSource[];

  id = 'chart1';
  width = 600;
  height = 400;
  type = 'column2d';
  dataFormat = 'json';
  dataSource: Object;

  public opisenseData:  OpisenseData[];

  constructor(private opisenseService: OpisenseService) {
    this.opisenseService.getSources().subscribe(result => {
      console.log(result);
      this.sources = result;
    });
  }

  clickSource(source) {
    this.opisenseService.getSourceVariables(source).subscribe(result => {
      if (result.length > 0) {
        this.opisenseService.getVariableData(result[0]).subscribe(dataResults => {
          this.opisenseData = dataResults;
          //const data = [];

          //dataResults.forEach((d: OpisenseData) => {
          //  //data.push({
          //  //  'label': d.date,
          //  //  'value': d.rawValue
          //  //});
          //  this.opisenseData = d;
          //});

          //this.dataSource = {
          //  'chart': {
          //    'caption': 'Last datapoints for source ' + source.name + ' (Id: ' + source.id + ')',
          //    'subCaption': 'Variable: ' + result[0].name + ' (Id: ' + result[0].id + ')',
          //    'theme': 'fint'
          //  },
          //  'data': data
          //};

        });
      }
    });
  }
}
