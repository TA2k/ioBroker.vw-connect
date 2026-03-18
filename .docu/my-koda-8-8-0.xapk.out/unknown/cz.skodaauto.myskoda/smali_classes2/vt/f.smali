.class public final Lvt/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/apache/http/client/ResponseHandler;


# instance fields
.field public final a:Lorg/apache/http/client/ResponseHandler;

.field public final b:Lzt/h;

.field public final c:Ltt/e;


# direct methods
.method public constructor <init>(Lorg/apache/http/client/ResponseHandler;Lzt/h;Ltt/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvt/f;->a:Lorg/apache/http/client/ResponseHandler;

    .line 5
    .line 6
    iput-object p2, p0, Lvt/f;->b:Lzt/h;

    .line 7
    .line 8
    iput-object p3, p0, Lvt/f;->c:Ltt/e;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final handleResponse(Lorg/apache/http/HttpResponse;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lvt/f;->c:Ltt/e;

    .line 2
    .line 3
    iget-object v1, p0, Lvt/f;->b:Lzt/h;

    .line 4
    .line 5
    invoke-virtual {v1}, Lzt/h;->j()J

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    invoke-virtual {v0, v1, v2}, Ltt/e;->o(J)V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Lvt/f;->c:Ltt/e;

    .line 13
    .line 14
    invoke-interface {p1}, Lorg/apache/http/HttpResponse;->getStatusLine()Lorg/apache/http/StatusLine;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-interface {v1}, Lorg/apache/http/StatusLine;->getStatusCode()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    invoke-virtual {v0, v1}, Ltt/e;->j(I)V

    .line 23
    .line 24
    .line 25
    invoke-static {p1}, Lvt/g;->a(Lorg/apache/http/HttpMessage;)Ljava/lang/Long;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    iget-object v1, p0, Lvt/f;->c:Ltt/e;

    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 34
    .line 35
    .line 36
    move-result-wide v2

    .line 37
    invoke-virtual {v1, v2, v3}, Ltt/e;->n(J)V

    .line 38
    .line 39
    .line 40
    :cond_0
    invoke-static {p1}, Lvt/g;->b(Lorg/apache/http/HttpResponse;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    if-eqz v0, :cond_1

    .line 45
    .line 46
    iget-object v1, p0, Lvt/f;->c:Ltt/e;

    .line 47
    .line 48
    invoke-virtual {v1, v0}, Ltt/e;->m(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    :cond_1
    iget-object v0, p0, Lvt/f;->c:Ltt/e;

    .line 52
    .line 53
    invoke-virtual {v0}, Ltt/e;->h()V

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Lvt/f;->a:Lorg/apache/http/client/ResponseHandler;

    .line 57
    .line 58
    invoke-interface {p0, p1}, Lorg/apache/http/client/ResponseHandler;->handleResponse(Lorg/apache/http/HttpResponse;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method
