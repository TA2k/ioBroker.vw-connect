.class public final synthetic Ln70/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lm70/s;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lm70/s;Lay0/a;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p4, p0, Ln70/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln70/i;->e:Lm70/s;

    .line 4
    .line 5
    iput-object p2, p0, Ln70/i;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, Ln70/i;->g:Ll2/b1;

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
    .locals 4

    .line 1
    iget v0, p0, Ln70/i;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    if-eqz p2, :cond_2

    .line 31
    .line 32
    iget-object p2, p0, Ln70/i;->e:Lm70/s;

    .line 33
    .line 34
    iget-object p2, p2, Lm70/s;->a:Lm70/p;

    .line 35
    .line 36
    if-eqz p2, :cond_1

    .line 37
    .line 38
    iget-object p2, p2, Lm70/p;->a:Ljava/lang/String;

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/4 p2, 0x0

    .line 42
    :goto_1
    const/16 v0, 0x180

    .line 43
    .line 44
    iget-object v1, p0, Ln70/i;->f:Lay0/a;

    .line 45
    .line 46
    iget-object p0, p0, Ln70/i;->g:Ll2/b1;

    .line 47
    .line 48
    invoke-static {p2, v1, p0, p1, v0}, Ln70/m;->j(Ljava/lang/String;Lay0/a;Ll2/b1;Ll2/o;I)V

    .line 49
    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 53
    .line 54
    .line 55
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 59
    .line 60
    const/4 v1, 0x2

    .line 61
    const/4 v2, 0x1

    .line 62
    if-eq v0, v1, :cond_3

    .line 63
    .line 64
    move v0, v2

    .line 65
    goto :goto_3

    .line 66
    :cond_3
    const/4 v0, 0x0

    .line 67
    :goto_3
    and-int/2addr p2, v2

    .line 68
    check-cast p1, Ll2/t;

    .line 69
    .line 70
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 71
    .line 72
    .line 73
    move-result p2

    .line 74
    if-eqz p2, :cond_4

    .line 75
    .line 76
    iget-object p2, p0, Ln70/i;->e:Lm70/s;

    .line 77
    .line 78
    iget-object v0, p2, Lm70/s;->d:Lxj0/j;

    .line 79
    .line 80
    new-instance v1, Ln70/i;

    .line 81
    .line 82
    const/4 v2, 0x1

    .line 83
    iget-object v3, p0, Ln70/i;->f:Lay0/a;

    .line 84
    .line 85
    iget-object p0, p0, Ln70/i;->g:Ll2/b1;

    .line 86
    .line 87
    invoke-direct {v1, p2, v3, p0, v2}, Ln70/i;-><init>(Lm70/s;Lay0/a;Ll2/b1;I)V

    .line 88
    .line 89
    .line 90
    const p0, 0x163d72db

    .line 91
    .line 92
    .line 93
    invoke-static {p0, p1, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    const/16 p2, 0x30

    .line 98
    .line 99
    invoke-static {v0, p0, p1, p2}, Lzj0/d;->b(Lxj0/j;Lt2/b;Ll2/o;I)V

    .line 100
    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 104
    .line 105
    .line 106
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 107
    .line 108
    return-object p0

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
