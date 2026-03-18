.class public final synthetic Lc41/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(IILay0/k;Ljava/util/List;)V
    .locals 0

    .line 1
    iput p2, p0, Lc41/h;->d:I

    .line 2
    .line 3
    iput-object p4, p0, Lc41/h;->e:Ljava/util/List;

    .line 4
    .line 5
    iput-object p3, p0, Lc41/h;->f:Lay0/k;

    .line 6
    .line 7
    iput p1, p0, Lc41/h;->g:I

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc41/h;->d:I

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
    iget p2, p0, Lc41/h;->g:I

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x1

    .line 16
    .line 17
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-object v0, p0, Lc41/h;->e:Ljava/util/List;

    .line 22
    .line 23
    iget-object p0, p0, Lc41/h;->f:Lay0/k;

    .line 24
    .line 25
    invoke-static {v0, p0, p1, p2}, Lz70/l;->V(Ljava/util/List;Lay0/k;Ll2/o;I)V

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
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 32
    .line 33
    .line 34
    iget p2, p0, Lc41/h;->g:I

    .line 35
    .line 36
    or-int/lit8 p2, p2, 0x1

    .line 37
    .line 38
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result p2

    .line 42
    iget-object v0, p0, Lc41/h;->e:Ljava/util/List;

    .line 43
    .line 44
    iget-object p0, p0, Lc41/h;->f:Lay0/k;

    .line 45
    .line 46
    invoke-static {v0, p0, p1, p2}, Lyj/f;->b(Ljava/util/List;Lay0/k;Ll2/o;I)V

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
    iget p2, p0, Lc41/h;->g:I

    .line 54
    .line 55
    or-int/lit8 p2, p2, 0x1

    .line 56
    .line 57
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    iget-object v0, p0, Lc41/h;->e:Ljava/util/List;

    .line 62
    .line 63
    iget-object p0, p0, Lc41/h;->f:Lay0/k;

    .line 64
    .line 65
    invoke-static {v0, p0, p1, p2}, Lyj/f;->c(Ljava/util/List;Lay0/k;Ll2/o;I)V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    iget p2, p0, Lc41/h;->g:I

    .line 73
    .line 74
    or-int/lit8 p2, p2, 0x1

    .line 75
    .line 76
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    iget-object v0, p0, Lc41/h;->e:Ljava/util/List;

    .line 81
    .line 82
    iget-object p0, p0, Lc41/h;->f:Lay0/k;

    .line 83
    .line 84
    invoke-static {v0, p0, p1, p2}, Ljp/yc;->a(Ljava/util/List;Lay0/k;Ll2/o;I)V

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    iget p2, p0, Lc41/h;->g:I

    .line 92
    .line 93
    or-int/lit8 p2, p2, 0x1

    .line 94
    .line 95
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 96
    .line 97
    .line 98
    move-result p2

    .line 99
    iget-object v0, p0, Lc41/h;->e:Ljava/util/List;

    .line 100
    .line 101
    iget-object p0, p0, Lc41/h;->f:Lay0/k;

    .line 102
    .line 103
    invoke-static {v0, p0, p1, p2}, Ljp/yc;->a(Ljava/util/List;Lay0/k;Ll2/o;I)V

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
