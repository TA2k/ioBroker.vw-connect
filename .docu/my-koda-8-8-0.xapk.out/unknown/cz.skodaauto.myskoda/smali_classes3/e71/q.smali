.class public final synthetic Le71/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;FLjava/lang/Object;Ljava/lang/Object;III)V
    .locals 0

    .line 1
    iput p7, p0, Le71/q;->d:I

    iput-object p1, p0, Le71/q;->h:Ljava/lang/Object;

    iput p2, p0, Le71/q;->e:F

    iput-object p3, p0, Le71/q;->i:Ljava/lang/Object;

    iput-object p4, p0, Le71/q;->j:Ljava/lang/Object;

    iput p5, p0, Le71/q;->f:I

    iput p6, p0, Le71/q;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;FLjava/lang/String;II)V
    .locals 1

    .line 2
    const/4 v0, 0x2

    iput v0, p0, Le71/q;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le71/q;->h:Ljava/lang/Object;

    iput-object p2, p0, Le71/q;->i:Ljava/lang/Object;

    iput p3, p0, Le71/q;->e:F

    iput-object p4, p0, Le71/q;->j:Ljava/lang/Object;

    iput p5, p0, Le71/q;->f:I

    iput p6, p0, Le71/q;->g:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Le71/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Le71/q;->h:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, Le71/q;->i:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Ljava/lang/String;

    .line 15
    .line 16
    iget-object v0, p0, Le71/q;->j:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v4, v0

    .line 19
    check-cast v4, Ljava/lang/String;

    .line 20
    .line 21
    move-object v5, p1

    .line 22
    check-cast v5, Ll2/o;

    .line 23
    .line 24
    check-cast p2, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    iget p1, p0, Le71/q;->f:I

    .line 30
    .line 31
    or-int/lit8 p1, p1, 0x1

    .line 32
    .line 33
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    iget v3, p0, Le71/q;->e:F

    .line 38
    .line 39
    iget v7, p0, Le71/q;->g:I

    .line 40
    .line 41
    invoke-static/range {v1 .. v7}, Lkp/c8;->a(Ljava/lang/String;Ljava/lang/String;FLjava/lang/String;Ll2/o;II)V

    .line 42
    .line 43
    .line 44
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_0
    iget-object v0, p0, Le71/q;->h:Ljava/lang/Object;

    .line 48
    .line 49
    move-object v1, v0

    .line 50
    check-cast v1, Ljava/lang/String;

    .line 51
    .line 52
    iget-object v0, p0, Le71/q;->i:Ljava/lang/Object;

    .line 53
    .line 54
    move-object v3, v0

    .line 55
    check-cast v3, Ljava/lang/String;

    .line 56
    .line 57
    iget-object v0, p0, Le71/q;->j:Ljava/lang/Object;

    .line 58
    .line 59
    move-object v4, v0

    .line 60
    check-cast v4, Lg4/p0;

    .line 61
    .line 62
    move-object v5, p1

    .line 63
    check-cast v5, Ll2/o;

    .line 64
    .line 65
    check-cast p2, Ljava/lang/Integer;

    .line 66
    .line 67
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    iget p1, p0, Le71/q;->f:I

    .line 71
    .line 72
    or-int/lit8 p1, p1, 0x1

    .line 73
    .line 74
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    iget v2, p0, Le71/q;->e:F

    .line 79
    .line 80
    iget v7, p0, Le71/q;->g:I

    .line 81
    .line 82
    invoke-static/range {v1 .. v7}, Lkp/c8;->c(Ljava/lang/String;FLjava/lang/String;Lg4/p0;Ll2/o;II)V

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :pswitch_1
    iget-object v0, p0, Le71/q;->h:Ljava/lang/Object;

    .line 87
    .line 88
    move-object v1, v0

    .line 89
    check-cast v1, Lx2/s;

    .line 90
    .line 91
    iget-object v0, p0, Le71/q;->i:Ljava/lang/Object;

    .line 92
    .line 93
    move-object v3, v0

    .line 94
    check-cast v3, Lh71/x;

    .line 95
    .line 96
    iget-object v0, p0, Le71/q;->j:Ljava/lang/Object;

    .line 97
    .line 98
    move-object v4, v0

    .line 99
    check-cast v4, Ljava/lang/Float;

    .line 100
    .line 101
    move-object v5, p1

    .line 102
    check-cast v5, Ll2/o;

    .line 103
    .line 104
    check-cast p2, Ljava/lang/Integer;

    .line 105
    .line 106
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    iget p1, p0, Le71/q;->f:I

    .line 110
    .line 111
    or-int/lit8 p1, p1, 0x1

    .line 112
    .line 113
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 114
    .line 115
    .line 116
    move-result v6

    .line 117
    iget v2, p0, Le71/q;->e:F

    .line 118
    .line 119
    iget v7, p0, Le71/q;->g:I

    .line 120
    .line 121
    invoke-static/range {v1 .. v7}, Lkp/w5;->d(Lx2/s;FLh71/x;Ljava/lang/Float;Ll2/o;II)V

    .line 122
    .line 123
    .line 124
    goto :goto_0

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
