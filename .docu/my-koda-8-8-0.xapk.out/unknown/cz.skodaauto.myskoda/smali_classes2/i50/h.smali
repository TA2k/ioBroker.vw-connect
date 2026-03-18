.class public final synthetic Li50/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc1/n0;

.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Lh50/v;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lc1/n0;Ll2/b1;Lh50/v;Lay0/a;Lay0/a;Lay0/a;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li50/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li50/h;->e:Lc1/n0;

    iput-object p2, p0, Li50/h;->f:Ll2/b1;

    iput-object p3, p0, Li50/h;->g:Lh50/v;

    iput-object p4, p0, Li50/h;->h:Lay0/a;

    iput-object p5, p0, Li50/h;->i:Lay0/a;

    iput-object p6, p0, Li50/h;->j:Lay0/a;

    iput-object p7, p0, Li50/h;->k:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lc1/n0;Ll2/b1;Lh50/v;Lay0/a;Lay0/a;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p8, 0x0

    iput p8, p0, Li50/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li50/h;->e:Lc1/n0;

    iput-object p2, p0, Li50/h;->f:Ll2/b1;

    iput-object p3, p0, Li50/h;->g:Lh50/v;

    iput-object p4, p0, Li50/h;->h:Lay0/a;

    iput-object p5, p0, Li50/h;->i:Lay0/a;

    iput-object p6, p0, Li50/h;->j:Lay0/a;

    iput-object p7, p0, Li50/h;->k:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Li50/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Integer;

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
    move-object v8, p1

    .line 25
    check-cast v8, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    const/16 v9, 0x30

    .line 34
    .line 35
    iget-object v1, p0, Li50/h;->e:Lc1/n0;

    .line 36
    .line 37
    iget-object v2, p0, Li50/h;->f:Ll2/b1;

    .line 38
    .line 39
    iget-object v3, p0, Li50/h;->g:Lh50/v;

    .line 40
    .line 41
    iget-object v4, p0, Li50/h;->h:Lay0/a;

    .line 42
    .line 43
    iget-object v5, p0, Li50/h;->i:Lay0/a;

    .line 44
    .line 45
    iget-object v6, p0, Li50/h;->j:Lay0/a;

    .line 46
    .line 47
    iget-object v7, p0, Li50/h;->k:Lay0/a;

    .line 48
    .line 49
    invoke-static/range {v1 .. v9}, Li50/s;->a(Lc1/n0;Ll2/b1;Lh50/v;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 54
    .line 55
    .line 56
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_0
    move-object v7, p1

    .line 60
    check-cast v7, Ll2/o;

    .line 61
    .line 62
    check-cast p2, Ljava/lang/Integer;

    .line 63
    .line 64
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    const/16 p1, 0x31

    .line 68
    .line 69
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 70
    .line 71
    .line 72
    move-result v8

    .line 73
    iget-object v0, p0, Li50/h;->e:Lc1/n0;

    .line 74
    .line 75
    iget-object v1, p0, Li50/h;->f:Ll2/b1;

    .line 76
    .line 77
    iget-object v2, p0, Li50/h;->g:Lh50/v;

    .line 78
    .line 79
    iget-object v3, p0, Li50/h;->h:Lay0/a;

    .line 80
    .line 81
    iget-object v4, p0, Li50/h;->i:Lay0/a;

    .line 82
    .line 83
    iget-object v5, p0, Li50/h;->j:Lay0/a;

    .line 84
    .line 85
    iget-object v6, p0, Li50/h;->k:Lay0/a;

    .line 86
    .line 87
    invoke-static/range {v0 .. v8}, Li50/s;->a(Lc1/n0;Ll2/b1;Lh50/v;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 88
    .line 89
    .line 90
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
