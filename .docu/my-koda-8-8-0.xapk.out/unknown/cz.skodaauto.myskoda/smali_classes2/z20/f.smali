.class public final synthetic Lz20/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/r8;

.field public final synthetic f:Lvy0/b0;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lay0/a;Lh2/r8;Lvy0/b0;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lz20/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lz20/f;->g:Lay0/a;

    iput-object p2, p0, Lz20/f;->h:Lay0/a;

    iput-object p3, p0, Lz20/f;->e:Lh2/r8;

    iput-object p4, p0, Lz20/f;->f:Lvy0/b0;

    return-void
.end method

.method public synthetic constructor <init>(Lh2/r8;Lvy0/b0;Lay0/a;Lay0/a;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lz20/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lz20/f;->e:Lh2/r8;

    iput-object p2, p0, Lz20/f;->f:Lvy0/b0;

    iput-object p3, p0, Lz20/f;->g:Lay0/a;

    iput-object p4, p0, Lz20/f;->h:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lz20/f;->d:I

    .line 2
    .line 3
    check-cast p1, Lk1/t;

    .line 4
    .line 5
    check-cast p2, Ll2/o;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    const-string v0, "$this$MaulModalBottomSheetLayout"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 p1, p3, 0x11

    .line 22
    .line 23
    const/16 v0, 0x10

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    if-eq p1, v0, :cond_0

    .line 27
    .line 28
    move p1, v1

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p1, 0x0

    .line 31
    :goto_0
    and-int/2addr p3, v1

    .line 32
    move-object v4, p2

    .line 33
    check-cast v4, Ll2/t;

    .line 34
    .line 35
    invoke-virtual {v4, p3, p1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-eqz p1, :cond_1

    .line 40
    .line 41
    const/4 v0, 0x0

    .line 42
    iget-object v1, p0, Lz20/f;->g:Lay0/a;

    .line 43
    .line 44
    iget-object v2, p0, Lz20/f;->h:Lay0/a;

    .line 45
    .line 46
    iget-object v3, p0, Lz20/f;->e:Lh2/r8;

    .line 47
    .line 48
    iget-object v5, p0, Lz20/f;->f:Lvy0/b0;

    .line 49
    .line 50
    invoke-static/range {v0 .. v5}, Lz70/l;->A(ILay0/a;Lay0/a;Lh2/r8;Ll2/o;Lvy0/b0;)V

    .line 51
    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_1
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 55
    .line 56
    .line 57
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_0
    const-string v0, "$this$MaulModalBottomSheetLayout"

    .line 61
    .line 62
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    and-int/lit8 p1, p3, 0x11

    .line 66
    .line 67
    const/16 v0, 0x10

    .line 68
    .line 69
    const/4 v1, 0x1

    .line 70
    if-eq p1, v0, :cond_2

    .line 71
    .line 72
    move p1, v1

    .line 73
    goto :goto_2

    .line 74
    :cond_2
    const/4 p1, 0x0

    .line 75
    :goto_2
    and-int/2addr p3, v1

    .line 76
    move-object v4, p2

    .line 77
    check-cast v4, Ll2/t;

    .line 78
    .line 79
    invoke-virtual {v4, p3, p1}, Ll2/t;->O(IZ)Z

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    if-eqz p1, :cond_3

    .line 84
    .line 85
    const/4 v0, 0x0

    .line 86
    iget-object v1, p0, Lz20/f;->g:Lay0/a;

    .line 87
    .line 88
    iget-object v2, p0, Lz20/f;->h:Lay0/a;

    .line 89
    .line 90
    iget-object v3, p0, Lz20/f;->e:Lh2/r8;

    .line 91
    .line 92
    iget-object v5, p0, Lz20/f;->f:Lvy0/b0;

    .line 93
    .line 94
    invoke-static/range {v0 .. v5}, Lz20/a;->h(ILay0/a;Lay0/a;Lh2/r8;Ll2/o;Lvy0/b0;)V

    .line 95
    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_3
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 99
    .line 100
    .line 101
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    return-object p0

    .line 104
    nop

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
