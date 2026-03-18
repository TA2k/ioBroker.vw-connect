.class public final synthetic Lcw0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lzv0/c;


# direct methods
.method public synthetic constructor <init>(Lzv0/c;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lcw0/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcw0/b;->e:Lzv0/c;

    return-void
.end method

.method public synthetic constructor <init>(Lzv0/c;Law0/h;)V
    .locals 0

    .line 2
    const/4 p2, 0x0

    iput p2, p0, Lcw0/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcw0/b;->e:Lzv0/c;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lcw0/b;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/Throwable;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lcw0/b;->e:Lzv0/c;

    .line 11
    .line 12
    iget-object p0, p0, Lzv0/c;->d:Lcw0/c;

    .line 13
    .line 14
    const/4 p1, 0x0

    .line 15
    invoke-static {p0, p1}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_0
    if-eqz p1, :cond_1

    .line 22
    .line 23
    iget-object p0, p0, Lcw0/b;->e:Lzv0/c;

    .line 24
    .line 25
    iget-object p0, p0, Lzv0/c;->n:Lj1/a;

    .line 26
    .line 27
    sget-object p1, Lmw0/a;->e:Lgv/a;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lj1/a;->w(Lgv/a;)V

    .line 30
    .line 31
    .line 32
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
