import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { catchError, map, Observable, of, tap } from 'rxjs';
import { environment } from 'src/environments/environments';
import { AuthResponse, User } from '../interfaces/auth.interface';


@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private baseUrl: string = environment.baseUrl;
  private _user!: User;

  get user() {
    return {...this._user};
  }

  constructor(private http: HttpClient) { }


  login(email: string, password: string) {
    const url: string = `${this.baseUrl}/auth`;
    const body = { email: email, password: password };

    return this.http.post<AuthResponse>(url, body)
      .pipe(
        tap(resp => {
          if (resp.ok){
            localStorage.setItem('token', resp.token!);
          }
        }),
        map( resp => resp.ok),
        catchError(err => of(err.error.msg))
      );
  }

  logout() {
    localStorage.clear();
    // localStorage.removeItem('token');
  }

  register(name: string, 
    email: string, password: string) {
    const url: string = `${this.baseUrl}/auth/new`;
    const body = { 
      name: name,
      email: email, 
      password: password 
    };

    return this.http.post<AuthResponse>(url, body)
      .pipe(
        tap(resp => {
          if (resp.ok){
            localStorage.setItem('token', resp.token!);
          }
        }),
        map( resp => resp.ok),
        catchError(err => of(err.error.msg))
      );
  }


  validateToken(): Observable<boolean> {
    const url: string = `${this.baseUrl}/auth/renew`;
    const headers = new HttpHeaders()
      .set('x-token', localStorage.getItem('token') || '');

    return this.http.get<AuthResponse>(url, { headers: headers})
      .pipe(
        map(resp => {
          localStorage.setItem('token', resp.token!);
          this._user = {
            name: resp.name!,
            uid: resp.uid!,
            email: resp.email!
          }

          return resp.ok;
        }),
        catchError(err => of(false))
      );
  }
  
}
