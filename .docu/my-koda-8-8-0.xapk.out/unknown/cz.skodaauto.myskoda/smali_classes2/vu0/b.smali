.class public final synthetic Lvu0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Luu0/r;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Luu0/r;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvu0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvu0/b;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Lvu0/b;->f:Luu0/r;

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
    .locals 2

    .line 1
    iget v0, p0, Lvu0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvu0/b;->f:Luu0/r;

    .line 7
    .line 8
    iget-object v0, v0, Luu0/r;->r:Lra0/c;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/4 v1, 0x3

    .line 15
    if-eq v0, v1, :cond_1

    .line 16
    .line 17
    const/4 v1, 0x7

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    const/16 v1, 0x8

    .line 21
    .line 22
    if-eq v0, v1, :cond_0

    .line 23
    .line 24
    sget-object v0, Luu0/o;->a:Luu0/o;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    sget-object v0, Luu0/n;->a:Luu0/n;

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    sget-object v0, Luu0/l;->a:Luu0/l;

    .line 31
    .line 32
    :goto_0
    iget-object p0, p0, Lvu0/b;->e:Lay0/k;

    .line 33
    .line 34
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    iget-object v0, p0, Lvu0/b;->f:Luu0/r;

    .line 41
    .line 42
    iget-object v0, v0, Luu0/r;->r:Lra0/c;

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    const/4 v1, 0x3

    .line 49
    if-eq v0, v1, :cond_3

    .line 50
    .line 51
    const/4 v1, 0x7

    .line 52
    if-eq v0, v1, :cond_2

    .line 53
    .line 54
    const/16 v1, 0x8

    .line 55
    .line 56
    if-eq v0, v1, :cond_2

    .line 57
    .line 58
    sget-object v0, Luu0/o;->a:Luu0/o;

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_2
    sget-object v0, Luu0/n;->a:Luu0/n;

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_3
    sget-object v0, Luu0/l;->a:Luu0/l;

    .line 65
    .line 66
    :goto_2
    iget-object p0, p0, Lvu0/b;->e:Lay0/k;

    .line 67
    .line 68
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    goto :goto_1

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
