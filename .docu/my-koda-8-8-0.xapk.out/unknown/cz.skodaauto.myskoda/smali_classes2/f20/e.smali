.class public final synthetic Lf20/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Le20/f;


# direct methods
.method public synthetic constructor <init>(Le20/f;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lf20/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf20/e;->e:Le20/f;

    return-void
.end method

.method public synthetic constructor <init>(Le20/f;II)V
    .locals 0

    .line 2
    iput p3, p0, Lf20/e;->d:I

    iput-object p1, p0, Lf20/e;->e:Le20/f;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lf20/e;->d:I

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
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x0

    .line 18
    const/4 v3, 0x1

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    move v0, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v2

    .line 24
    :goto_0
    and-int/2addr p2, v3

    .line 25
    check-cast p1, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_1

    .line 32
    .line 33
    sget-object p2, Lk1/t;->a:Lk1/t;

    .line 34
    .line 35
    iget-object p0, p0, Lf20/e;->e:Le20/f;

    .line 36
    .line 37
    invoke-static {p2, p0, p1, v2}, Lf20/j;->d(Lk1/t;Le20/f;Ll2/o;I)V

    .line 38
    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 42
    .line 43
    .line 44
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    const/4 p2, 0x1

    .line 51
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 52
    .line 53
    .line 54
    move-result p2

    .line 55
    iget-object p0, p0, Lf20/e;->e:Le20/f;

    .line 56
    .line 57
    invoke-static {p0, p1, p2}, Lf20/j;->e(Le20/f;Ll2/o;I)V

    .line 58
    .line 59
    .line 60
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    const/4 p2, 0x1

    .line 67
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 68
    .line 69
    .line 70
    move-result p2

    .line 71
    iget-object p0, p0, Lf20/e;->e:Le20/f;

    .line 72
    .line 73
    invoke-static {p0, p1, p2}, Lf20/j;->b(Le20/f;Ll2/o;I)V

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
