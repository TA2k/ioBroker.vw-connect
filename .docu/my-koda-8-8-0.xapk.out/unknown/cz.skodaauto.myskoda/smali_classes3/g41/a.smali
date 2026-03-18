.class public final synthetic Lg41/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz70/d;

.field public final synthetic f:Lt31/o;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lz70/d;Lt31/o;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lg41/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lg41/a;->e:Lz70/d;

    iput-object p2, p0, Lg41/a;->f:Lt31/o;

    iput-object p3, p0, Lg41/a;->g:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lz70/d;Lt31/o;Lay0/k;II)V
    .locals 0

    .line 2
    iput p5, p0, Lg41/a;->d:I

    iput-object p1, p0, Lg41/a;->e:Lz70/d;

    iput-object p2, p0, Lg41/a;->f:Lt31/o;

    iput-object p3, p0, Lg41/a;->g:Lay0/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lg41/a;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/16 p2, 0x41

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget-object v0, p0, Lg41/a;->e:Lz70/d;

    .line 20
    .line 21
    iget-object v1, p0, Lg41/a;->f:Lt31/o;

    .line 22
    .line 23
    iget-object p0, p0, Lg41/a;->g:Lay0/k;

    .line 24
    .line 25
    invoke-static {v0, v1, p0, p1, p2}, Lkp/n8;->d(Lz70/d;Lt31/o;Lay0/k;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const/16 p2, 0x41

    .line 35
    .line 36
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    iget-object v0, p0, Lg41/a;->e:Lz70/d;

    .line 41
    .line 42
    iget-object v1, p0, Lg41/a;->f:Lt31/o;

    .line 43
    .line 44
    iget-object p0, p0, Lg41/a;->g:Lay0/k;

    .line 45
    .line 46
    invoke-static {v0, v1, p0, p1, p2}, Lkp/n8;->c(Lz70/d;Lt31/o;Lay0/k;Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    and-int/lit8 v0, p2, 0x3

    .line 55
    .line 56
    const/4 v1, 0x2

    .line 57
    const/4 v2, 0x1

    .line 58
    if-eq v0, v1, :cond_0

    .line 59
    .line 60
    move v0, v2

    .line 61
    goto :goto_1

    .line 62
    :cond_0
    const/4 v0, 0x0

    .line 63
    :goto_1
    and-int/2addr p2, v2

    .line 64
    check-cast p1, Ll2/t;

    .line 65
    .line 66
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    if-eqz p2, :cond_1

    .line 71
    .line 72
    const/16 p2, 0x40

    .line 73
    .line 74
    iget-object v0, p0, Lg41/a;->e:Lz70/d;

    .line 75
    .line 76
    iget-object v1, p0, Lg41/a;->f:Lt31/o;

    .line 77
    .line 78
    iget-object p0, p0, Lg41/a;->g:Lay0/k;

    .line 79
    .line 80
    invoke-static {v0, v1, p0, p1, p2}, Lkp/n8;->c(Lz70/d;Lt31/o;Lay0/k;Ll2/o;I)V

    .line 81
    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 85
    .line 86
    .line 87
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object p0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
