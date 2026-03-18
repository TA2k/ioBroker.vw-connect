.class public final Llm/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/k;
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final e:Ld01/j;

.field public final f:Lvy0/l;


# direct methods
.method public synthetic constructor <init>(Ld01/j;Lvy0/l;I)V
    .locals 0

    .line 1
    iput p3, p0, Llm/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Llm/c;->e:Ld01/j;

    .line 4
    .line 5
    iput-object p2, p0, Llm/c;->f:Lvy0/l;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Llm/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Throwable;

    .line 7
    .line 8
    :try_start_0
    iget-object p0, p0, Llm/c;->e:Ld01/j;

    .line 9
    .line 10
    invoke-interface {p0}, Ld01/j;->cancel()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    .line 12
    .line 13
    :catchall_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_0
    check-cast p1, Ljava/lang/Throwable;

    .line 17
    .line 18
    :try_start_1
    iget-object p0, p0, Llm/c;->e:Ld01/j;

    .line 19
    .line 20
    invoke-interface {p0}, Ld01/j;->cancel()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 21
    .line 22
    .line 23
    :catchall_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onFailure(Ld01/j;Ljava/io/IOException;)V
    .locals 1

    .line 1
    iget v0, p0, Llm/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Ld01/j;->isCanceled()Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Llm/c;->f:Lvy0/l;

    .line 13
    .line 14
    invoke-static {p2}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void

    .line 22
    :pswitch_0
    invoke-interface {p1}, Ld01/j;->isCanceled()Z

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    if-nez p1, :cond_1

    .line 27
    .line 28
    iget-object p0, p0, Llm/c;->f:Lvy0/l;

    .line 29
    .line 30
    invoke-static {p2}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    :cond_1
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onResponse(Ld01/j;Ld01/t0;)V
    .locals 0

    .line 1
    iget p1, p0, Llm/c;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Llm/c;->f:Lvy0/l;

    .line 7
    .line 8
    invoke-virtual {p0, p2}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    iget-object p0, p0, Llm/c;->f:Lvy0/l;

    .line 13
    .line 14
    invoke-virtual {p0, p2}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
