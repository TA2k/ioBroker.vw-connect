.class public final synthetic La71/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Lh2/m0;

.field public final synthetic g:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lvy0/b0;Lh2/m0;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p4, p0, La71/v0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La71/v0;->e:Lvy0/b0;

    .line 4
    .line 5
    iput-object p2, p0, La71/v0;->f:Lh2/m0;

    .line 6
    .line 7
    iput-object p3, p0, La71/v0;->g:Ll2/b1;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, La71/v0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, La71/x0;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    iget-object v2, p0, La71/v0;->f:Lh2/m0;

    .line 10
    .line 11
    iget-object v3, p0, La71/v0;->g:Ll2/b1;

    .line 12
    .line 13
    const/4 v4, 0x0

    .line 14
    invoke-direct {v0, v2, v3, v4, v1}, La71/x0;-><init>(Lh2/m0;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x3

    .line 18
    iget-object p0, p0, La71/v0;->e:Lvy0/b0;

    .line 19
    .line 20
    invoke-static {p0, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 21
    .line 22
    .line 23
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    new-instance v0, La71/x0;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    iget-object v2, p0, La71/v0;->f:Lh2/m0;

    .line 30
    .line 31
    iget-object v3, p0, La71/v0;->g:Ll2/b1;

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    invoke-direct {v0, v2, v3, v4, v1}, La71/x0;-><init>(Lh2/m0;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 v1, 0x3

    .line 38
    iget-object p0, p0, La71/v0;->e:Lvy0/b0;

    .line 39
    .line 40
    invoke-static {p0, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
