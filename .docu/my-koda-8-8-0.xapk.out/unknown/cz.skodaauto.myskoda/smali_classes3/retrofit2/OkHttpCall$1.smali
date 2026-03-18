.class Lretrofit2/OkHttpCall$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/k;


# instance fields
.field public final synthetic d:Lretrofit2/Callback;

.field public final synthetic e:Lretrofit2/OkHttpCall;


# direct methods
.method public constructor <init>(Lretrofit2/OkHttpCall;Lretrofit2/Callback;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/OkHttpCall$1;->e:Lretrofit2/OkHttpCall;

    .line 5
    .line 6
    iput-object p2, p0, Lretrofit2/OkHttpCall$1;->d:Lretrofit2/Callback;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onFailure(Ld01/j;Ljava/io/IOException;)V
    .locals 0

    .line 1
    :try_start_0
    iget-object p1, p0, Lretrofit2/OkHttpCall$1;->d:Lretrofit2/Callback;

    .line 2
    .line 3
    iget-object p0, p0, Lretrofit2/OkHttpCall$1;->e:Lretrofit2/OkHttpCall;

    .line 4
    .line 5
    invoke-interface {p1, p0, p2}, Lretrofit2/Callback;->a(Lretrofit2/Call;Ljava/lang/Throwable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :catchall_0
    move-exception p0

    .line 10
    invoke-static {p0}, Lretrofit2/Utils;->m(Ljava/lang/Throwable;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Throwable;->printStackTrace()V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final onResponse(Ld01/j;Ld01/t0;)V
    .locals 0

    .line 1
    iget-object p1, p0, Lretrofit2/OkHttpCall$1;->d:Lretrofit2/Callback;

    .line 2
    .line 3
    iget-object p0, p0, Lretrofit2/OkHttpCall$1;->e:Lretrofit2/OkHttpCall;

    .line 4
    .line 5
    :try_start_0
    invoke-virtual {p0, p2}, Lretrofit2/OkHttpCall;->c(Ld01/t0;)Lretrofit2/Response;

    .line 6
    .line 7
    .line 8
    move-result-object p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 9
    :try_start_1
    invoke-interface {p1, p0, p2}, Lretrofit2/Callback;->b(Lretrofit2/Call;Lretrofit2/Response;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    invoke-static {p0}, Lretrofit2/Utils;->m(Ljava/lang/Throwable;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Throwable;->printStackTrace()V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catchall_1
    move-exception p2

    .line 22
    invoke-static {p2}, Lretrofit2/Utils;->m(Ljava/lang/Throwable;)V

    .line 23
    .line 24
    .line 25
    :try_start_2
    invoke-interface {p1, p0, p2}, Lretrofit2/Callback;->a(Lretrofit2/Call;Ljava/lang/Throwable;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catchall_2
    move-exception p0

    .line 30
    invoke-static {p0}, Lretrofit2/Utils;->m(Ljava/lang/Throwable;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/lang/Throwable;->printStackTrace()V

    .line 34
    .line 35
    .line 36
    :goto_0
    return-void
.end method
