.class public final synthetic Li40/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/e1;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh40/e1;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li40/t0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/t0;->e:Lh40/e1;

    iput-object p2, p0, Li40/t0;->f:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lh40/e1;Lay0/a;II)V
    .locals 0

    .line 2
    iput p4, p0, Li40/t0;->d:I

    iput-object p1, p0, Li40/t0;->e:Lh40/e1;

    iput-object p2, p0, Li40/t0;->f:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Li40/t0;->d:I

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
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object v0, p0, Li40/t0;->e:Lh40/e1;

    .line 19
    .line 20
    iget-object p0, p0, Li40/t0;->f:Lay0/a;

    .line 21
    .line 22
    invoke-static {v0, p0, p1, p2}, Li40/x0;->b(Lh40/e1;Lay0/a;Ll2/o;I)V

    .line 23
    .line 24
    .line 25
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result p2

    .line 32
    and-int/lit8 v0, p2, 0x3

    .line 33
    .line 34
    const/4 v1, 0x2

    .line 35
    const/4 v2, 0x0

    .line 36
    const/4 v3, 0x1

    .line 37
    if-eq v0, v1, :cond_0

    .line 38
    .line 39
    move v0, v3

    .line 40
    goto :goto_1

    .line 41
    :cond_0
    move v0, v2

    .line 42
    :goto_1
    and-int/2addr p2, v3

    .line 43
    check-cast p1, Ll2/t;

    .line 44
    .line 45
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    iget-object p2, p0, Li40/t0;->e:Lh40/e1;

    .line 52
    .line 53
    iget-object p0, p0, Li40/t0;->f:Lay0/a;

    .line 54
    .line 55
    invoke-static {p2, p0, p1, v2}, Li40/x0;->b(Lh40/e1;Lay0/a;Ll2/o;I)V

    .line 56
    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 60
    .line 61
    .line 62
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    const/4 p2, 0x1

    .line 69
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 70
    .line 71
    .line 72
    move-result p2

    .line 73
    iget-object v0, p0, Li40/t0;->e:Lh40/e1;

    .line 74
    .line 75
    iget-object p0, p0, Li40/t0;->f:Lay0/a;

    .line 76
    .line 77
    invoke-static {v0, p0, p1, p2}, Li40/x0;->f(Lh40/e1;Lay0/a;Ll2/o;I)V

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
