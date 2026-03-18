.class public final synthetic Lxo/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lxo/f;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:[B


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;II[BI)V
    .locals 0

    .line 1
    iput p5, p0, Lxo/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxo/b;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput p2, p0, Lxo/b;->f:I

    .line 6
    .line 7
    iput p3, p0, Lxo/b;->g:I

    .line 8
    .line 9
    iput-object p4, p0, Lxo/b;->h:[B

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final c(Lj51/b;)V
    .locals 4

    .line 1
    iget v0, p0, Lxo/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const-string v0, "digitalKeyId"

    .line 10
    .line 11
    iget-object v1, p0, Lxo/b;->e:Ljava/lang/String;

    .line 12
    .line 13
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "data"

    .line 17
    .line 18
    iget-object v2, p0, Lxo/b;->h:[B

    .line 19
    .line 20
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object p1, p1, Lj51/b;->a:Lxy0/x;

    .line 24
    .line 25
    new-instance v0, Lk51/e;

    .line 26
    .line 27
    iget v3, p0, Lxo/b;->f:I

    .line 28
    .line 29
    iget p0, p0, Lxo/b;->g:I

    .line 30
    .line 31
    invoke-direct {v0, v3, p0, v1, v2}, Lk51/e;-><init>(IILjava/lang/String;[B)V

    .line 32
    .line 33
    .line 34
    check-cast p1, Lxy0/w;

    .line 35
    .line 36
    invoke-virtual {p1, v0}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :pswitch_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    const-string v0, "digitalKeyId"

    .line 44
    .line 45
    iget-object v1, p0, Lxo/b;->e:Ljava/lang/String;

    .line 46
    .line 47
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const-string v0, "data"

    .line 51
    .line 52
    iget-object v2, p0, Lxo/b;->h:[B

    .line 53
    .line 54
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 58
    .line 59
    invoke-static {p1}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    iget-object v0, v0, Lx51/b;->d:La61/a;

    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    iget-object p1, p1, Lj51/b;->a:Lxy0/x;

    .line 68
    .line 69
    new-instance v0, Lk51/b;

    .line 70
    .line 71
    iget v3, p0, Lxo/b;->f:I

    .line 72
    .line 73
    iget p0, p0, Lxo/b;->g:I

    .line 74
    .line 75
    invoke-direct {v0, v3, p0, v1, v2}, Lk51/b;-><init>(IILjava/lang/String;[B)V

    .line 76
    .line 77
    .line 78
    check-cast p1, Lxy0/w;

    .line 79
    .line 80
    invoke-virtual {p1, v0}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
