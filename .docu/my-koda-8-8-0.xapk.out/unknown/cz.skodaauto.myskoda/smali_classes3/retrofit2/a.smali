.class public final synthetic Lretrofit2/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;

.field public final synthetic f:Lretrofit2/Callback;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;Lretrofit2/Callback;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lretrofit2/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lretrofit2/a;->e:Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;

    .line 4
    .line 5
    iput-object p2, p0, Lretrofit2/a;->f:Lretrofit2/Callback;

    .line 6
    .line 7
    iput-object p3, p0, Lretrofit2/a;->g:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    .line 1
    iget v0, p0, Lretrofit2/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lretrofit2/a;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/lang/Throwable;

    .line 9
    .line 10
    iget-object v1, p0, Lretrofit2/a;->e:Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;

    .line 11
    .line 12
    iget-object v1, v1, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;->e:Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;

    .line 13
    .line 14
    iget-object p0, p0, Lretrofit2/a;->f:Lretrofit2/Callback;

    .line 15
    .line 16
    invoke-interface {p0, v1, v0}, Lretrofit2/Callback;->a(Lretrofit2/Call;Ljava/lang/Throwable;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :pswitch_0
    iget-object v0, p0, Lretrofit2/a;->g:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v0, Lretrofit2/Response;

    .line 23
    .line 24
    iget-object v1, p0, Lretrofit2/a;->e:Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;

    .line 25
    .line 26
    iget-object v1, v1, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall$1;->e:Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;

    .line 27
    .line 28
    iget-object v2, v1, Lretrofit2/DefaultCallAdapterFactory$ExecutorCallbackCall;->e:Lretrofit2/Call;

    .line 29
    .line 30
    invoke-interface {v2}, Lretrofit2/Call;->isCanceled()Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    iget-object p0, p0, Lretrofit2/a;->f:Lretrofit2/Callback;

    .line 35
    .line 36
    if-eqz v2, :cond_0

    .line 37
    .line 38
    new-instance v0, Ljava/io/IOException;

    .line 39
    .line 40
    const-string v2, "Canceled"

    .line 41
    .line 42
    invoke-direct {v0, v2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-interface {p0, v1, v0}, Lretrofit2/Callback;->a(Lretrofit2/Call;Ljava/lang/Throwable;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-interface {p0, v1, v0}, Lretrofit2/Callback;->b(Lretrofit2/Call;Lretrofit2/Response;)V

    .line 50
    .line 51
    .line 52
    :goto_0
    return-void

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
