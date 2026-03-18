.class public final synthetic Lzb/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Lkn/c0;


# direct methods
.method public synthetic constructor <init>(Lvy0/b0;Lkn/c0;I)V
    .locals 0

    .line 1
    iput p3, p0, Lzb/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lzb/c;->e:Lvy0/b0;

    .line 4
    .line 5
    iput-object p2, p0, Lzb/c;->f:Lkn/c0;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lzb/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lkn/d;

    .line 7
    .line 8
    const/4 v1, 0x7

    .line 9
    iget-object v2, p0, Lzb/c;->f:Lkn/c0;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-direct {v0, v2, v3, v1}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    iget-object p0, p0, Lzb/c;->e:Lvy0/b0;

    .line 17
    .line 18
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 19
    .line 20
    .line 21
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    new-instance v0, Lkn/d;

    .line 25
    .line 26
    const/4 v1, 0x6

    .line 27
    iget-object v2, p0, Lzb/c;->f:Lkn/c0;

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    invoke-direct {v0, v2, v3, v1}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    const/4 v1, 0x3

    .line 34
    iget-object p0, p0, Lzb/c;->e:Lvy0/b0;

    .line 35
    .line 36
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :pswitch_1
    new-instance v0, Lkn/d;

    .line 41
    .line 42
    const/4 v1, 0x5

    .line 43
    iget-object v2, p0, Lzb/c;->f:Lkn/c0;

    .line 44
    .line 45
    const/4 v3, 0x0

    .line 46
    invoke-direct {v0, v2, v3, v1}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 47
    .line 48
    .line 49
    const/4 v1, 0x3

    .line 50
    iget-object p0, p0, Lzb/c;->e:Lvy0/b0;

    .line 51
    .line 52
    invoke-static {p0, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
