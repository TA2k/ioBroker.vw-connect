.class public final synthetic Lk41/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lh2/r8;


# direct methods
.method public synthetic constructor <init>(Lvy0/b0;Lay0/k;Lh2/r8;I)V
    .locals 0

    .line 1
    iput p4, p0, Lk41/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lk41/d;->e:Lvy0/b0;

    .line 4
    .line 5
    iput-object p2, p0, Lk41/d;->f:Lay0/k;

    .line 6
    .line 7
    iput-object p3, p0, Lk41/d;->g:Lh2/r8;

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
    .locals 4

    .line 1
    iget v0, p0, Lk41/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh2/i0;

    .line 7
    .line 8
    const/16 v1, 0x15

    .line 9
    .line 10
    iget-object v2, p0, Lk41/d;->g:Lh2/r8;

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct {v0, v2, v3, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    const/4 v1, 0x3

    .line 17
    iget-object v2, p0, Lk41/d;->e:Lvy0/b0;

    .line 18
    .line 19
    invoke-static {v2, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 20
    .line 21
    .line 22
    sget-object v0, Lx31/c;->a:Lx31/c;

    .line 23
    .line 24
    iget-object p0, p0, Lk41/d;->f:Lay0/k;

    .line 25
    .line 26
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_0
    new-instance v0, Lh2/i0;

    .line 33
    .line 34
    const/16 v1, 0x14

    .line 35
    .line 36
    iget-object v2, p0, Lk41/d;->g:Lh2/r8;

    .line 37
    .line 38
    const/4 v3, 0x0

    .line 39
    invoke-direct {v0, v2, v3, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    const/4 v1, 0x3

    .line 43
    iget-object v2, p0, Lk41/d;->e:Lvy0/b0;

    .line 44
    .line 45
    invoke-static {v2, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 46
    .line 47
    .line 48
    sget-object v0, Lx31/a;->a:Lx31/a;

    .line 49
    .line 50
    iget-object p0, p0, Lk41/d;->f:Lay0/k;

    .line 51
    .line 52
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
