.class public final Law0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Low0/r;
.implements Lvy0/b0;


# instance fields
.field public final synthetic d:I

.field public final e:Lpx0/g;

.field public final f:Low0/v;

.field public final g:Low0/u;

.field public final h:Lxw0/d;

.field public final i:Lxw0/d;

.field public final j:Low0/m;

.field public final k:Law0/c;

.field public final l:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Law0/c;Lkw0/f;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Law0/h;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Law0/h;->k:Law0/c;

    .line 3
    iget-object p1, p2, Lkw0/f;->f:Lpx0/g;

    .line 4
    iput-object p1, p0, Law0/h;->e:Lpx0/g;

    .line 5
    iget-object p1, p2, Lkw0/f;->a:Low0/v;

    .line 6
    iput-object p1, p0, Law0/h;->f:Low0/v;

    .line 7
    iget-object p1, p2, Lkw0/f;->d:Low0/u;

    .line 8
    iput-object p1, p0, Law0/h;->g:Low0/u;

    .line 9
    iget-object p1, p2, Lkw0/f;->b:Lxw0/d;

    .line 10
    iput-object p1, p0, Law0/h;->h:Lxw0/d;

    .line 11
    iget-object p1, p2, Lkw0/f;->g:Lxw0/d;

    .line 12
    iput-object p1, p0, Law0/h;->i:Lxw0/d;

    .line 13
    iget-object p1, p2, Lkw0/f;->e:Ljava/lang/Object;

    .line 14
    instance-of v0, p1, Lio/ktor/utils/io/t;

    if-eqz v0, :cond_0

    check-cast p1, Lio/ktor/utils/io/t;

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-nez p1, :cond_1

    .line 15
    sget-object p1, Lio/ktor/utils/io/t;->a:Lio/ktor/utils/io/s;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    sget-object p1, Lio/ktor/utils/io/s;->b:Lio/ktor/utils/io/r;

    .line 17
    :cond_1
    iput-object p1, p0, Law0/h;->l:Ljava/lang/Object;

    .line 18
    iget-object p1, p2, Lkw0/f;->c:Low0/m;

    .line 19
    iput-object p1, p0, Law0/h;->j:Low0/m;

    return-void
.end method

.method public constructor <init>(Law0/f;[BLaw0/h;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Law0/h;->d:I

    .line 20
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 21
    iput-object p1, p0, Law0/h;->k:Law0/c;

    .line 22
    iput-object p2, p0, Law0/h;->l:Ljava/lang/Object;

    .line 23
    invoke-virtual {p3}, Law0/h;->c()Low0/v;

    move-result-object p1

    iput-object p1, p0, Law0/h;->f:Low0/v;

    .line 24
    iget p1, p3, Law0/h;->d:I

    packed-switch p1, :pswitch_data_0

    .line 25
    iget-object p1, p3, Law0/h;->g:Low0/u;

    goto :goto_0

    .line 26
    :pswitch_0
    iget-object p1, p3, Law0/h;->g:Low0/u;

    .line 27
    :goto_0
    iput-object p1, p0, Law0/h;->g:Low0/u;

    .line 28
    iget p1, p3, Law0/h;->d:I

    packed-switch p1, :pswitch_data_1

    .line 29
    iget-object p1, p3, Law0/h;->h:Lxw0/d;

    goto :goto_1

    .line 30
    :pswitch_1
    iget-object p1, p3, Law0/h;->h:Lxw0/d;

    .line 31
    :goto_1
    iput-object p1, p0, Law0/h;->h:Lxw0/d;

    .line 32
    iget p1, p3, Law0/h;->d:I

    packed-switch p1, :pswitch_data_2

    .line 33
    iget-object p1, p3, Law0/h;->i:Lxw0/d;

    goto :goto_2

    .line 34
    :pswitch_2
    iget-object p1, p3, Law0/h;->i:Lxw0/d;

    .line 35
    :goto_2
    iput-object p1, p0, Law0/h;->i:Lxw0/d;

    .line 36
    invoke-interface {p3}, Low0/r;->a()Low0/m;

    move-result-object p1

    iput-object p1, p0, Law0/h;->j:Low0/m;

    .line 37
    invoke-interface {p3}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    move-result-object p1

    iput-object p1, p0, Law0/h;->e:Lpx0/g;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch

    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_1
    .end packed-switch

    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_2
    .end packed-switch
.end method


# virtual methods
.method public final M()Law0/c;
    .locals 1

    .line 1
    iget v0, p0, Law0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Law0/h;->k:Law0/c;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Law0/h;->k:Law0/c;

    .line 10
    .line 11
    check-cast p0, Law0/f;

    .line 12
    .line 13
    return-object p0

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final a()Low0/m;
    .locals 1

    .line 1
    iget v0, p0, Law0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Law0/h;->j:Low0/m;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Law0/h;->j:Low0/m;

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b()Lio/ktor/utils/io/t;
    .locals 2

    .line 1
    iget v0, p0, Law0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Law0/h;->l:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lio/ktor/utils/io/t;

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Law0/h;->l:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, [B

    .line 14
    .line 15
    array-length v0, p0

    .line 16
    new-instance v1, Lnz0/a;

    .line 17
    .line 18
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1, v0, p0}, Lnz0/a;->k(I[B)V

    .line 22
    .line 23
    .line 24
    new-instance p0, Lio/ktor/utils/io/q0;

    .line 25
    .line 26
    invoke-direct {p0, v1}, Lio/ktor/utils/io/q0;-><init>(Lnz0/a;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final c()Low0/v;
    .locals 1

    .line 1
    iget v0, p0, Law0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Law0/h;->f:Low0/v;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Law0/h;->f:Low0/v;

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 1

    .line 1
    iget v0, p0, Law0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Law0/h;->e:Lpx0/g;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Law0/h;->e:Lpx0/g;

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "HttpResponse["

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Lo5/c;->c(Law0/h;)Lkw0/b;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-interface {v1}, Lkw0/b;->getUrl()Low0/f0;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v1, ", "

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Law0/h;->c()Low0/v;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const/16 p0, 0x5d

    .line 32
    .line 33
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method
