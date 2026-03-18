.class public final synthetic Lx80/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lw80/d;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lw80/d;Lay0/a;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lx80/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lx80/c;->e:Lw80/d;

    iput-object p2, p0, Lx80/c;->f:Lay0/a;

    iput-object p3, p0, Lx80/c;->g:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lw80/d;Lay0/a;Lay0/a;II)V
    .locals 0

    .line 2
    iput p5, p0, Lx80/c;->d:I

    iput-object p1, p0, Lx80/c;->e:Lw80/d;

    iput-object p2, p0, Lx80/c;->f:Lay0/a;

    iput-object p3, p0, Lx80/c;->g:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lx80/c;->d:I

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
    iget-object v0, p0, Lx80/c;->e:Lw80/d;

    .line 19
    .line 20
    iget-object v1, p0, Lx80/c;->f:Lay0/a;

    .line 21
    .line 22
    iget-object p0, p0, Lx80/c;->g:Lay0/a;

    .line 23
    .line 24
    invoke-static {v0, v1, p0, p1, p2}, Lx80/d;->a(Lw80/d;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 25
    .line 26
    .line 27
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    const/4 p2, 0x1

    .line 34
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    iget-object v0, p0, Lx80/c;->e:Lw80/d;

    .line 39
    .line 40
    iget-object v1, p0, Lx80/c;->f:Lay0/a;

    .line 41
    .line 42
    iget-object p0, p0, Lx80/c;->g:Lay0/a;

    .line 43
    .line 44
    invoke-static {v0, v1, p0, p1, p2}, Lx80/d;->a(Lw80/d;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 49
    .line 50
    .line 51
    move-result p2

    .line 52
    and-int/lit8 v0, p2, 0x3

    .line 53
    .line 54
    const/4 v1, 0x2

    .line 55
    const/4 v2, 0x0

    .line 56
    const/4 v3, 0x1

    .line 57
    if-eq v0, v1, :cond_0

    .line 58
    .line 59
    move v0, v3

    .line 60
    goto :goto_1

    .line 61
    :cond_0
    move v0, v2

    .line 62
    :goto_1
    and-int/2addr p2, v3

    .line 63
    check-cast p1, Ll2/t;

    .line 64
    .line 65
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 66
    .line 67
    .line 68
    move-result p2

    .line 69
    if-eqz p2, :cond_1

    .line 70
    .line 71
    iget-object p2, p0, Lx80/c;->e:Lw80/d;

    .line 72
    .line 73
    iget-object v0, p0, Lx80/c;->f:Lay0/a;

    .line 74
    .line 75
    iget-object p0, p0, Lx80/c;->g:Lay0/a;

    .line 76
    .line 77
    invoke-static {p2, v0, p0, p1, v2}, Lx80/d;->a(Lw80/d;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 78
    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 82
    .line 83
    .line 84
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
