.class public final synthetic Lr30/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Lq30/g;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Le1/n1;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Lq30/g;Lay0/k;Lay0/a;Le1/n1;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lr30/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lr30/c;->e:Ljava/util/List;

    iput-object p2, p0, Lr30/c;->f:Lq30/g;

    iput-object p3, p0, Lr30/c;->g:Lay0/k;

    iput-object p4, p0, Lr30/c;->h:Lay0/a;

    iput-object p5, p0, Lr30/c;->i:Le1/n1;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Lq30/g;Lay0/k;Lay0/a;Le1/n1;I)V
    .locals 0

    .line 2
    const/4 p6, 0x1

    iput p6, p0, Lr30/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lr30/c;->e:Ljava/util/List;

    iput-object p2, p0, Lr30/c;->f:Lq30/g;

    iput-object p3, p0, Lr30/c;->g:Lay0/k;

    iput-object p4, p0, Lr30/c;->h:Lay0/a;

    iput-object p5, p0, Lr30/c;->i:Le1/n1;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lr30/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v6, p1

    .line 7
    check-cast v6, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v7

    .line 19
    iget-object v1, p0, Lr30/c;->e:Ljava/util/List;

    .line 20
    .line 21
    iget-object v2, p0, Lr30/c;->f:Lq30/g;

    .line 22
    .line 23
    iget-object v3, p0, Lr30/c;->g:Lay0/k;

    .line 24
    .line 25
    iget-object v4, p0, Lr30/c;->h:Lay0/a;

    .line 26
    .line 27
    iget-object v5, p0, Lr30/c;->i:Le1/n1;

    .line 28
    .line 29
    invoke-static/range {v1 .. v7}, Lr30/h;->d(Ljava/util/List;Lq30/g;Lay0/k;Lay0/a;Le1/n1;Ll2/o;I)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 36
    .line 37
    check-cast p2, Ljava/lang/Integer;

    .line 38
    .line 39
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result p2

    .line 43
    and-int/lit8 v0, p2, 0x3

    .line 44
    .line 45
    const/4 v1, 0x2

    .line 46
    const/4 v2, 0x1

    .line 47
    if-eq v0, v1, :cond_0

    .line 48
    .line 49
    move v0, v2

    .line 50
    goto :goto_0

    .line 51
    :cond_0
    const/4 v0, 0x0

    .line 52
    :goto_0
    and-int/2addr p2, v2

    .line 53
    move-object v6, p1

    .line 54
    check-cast v6, Ll2/t;

    .line 55
    .line 56
    invoke-virtual {v6, p2, v0}, Ll2/t;->O(IZ)Z

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    if-eqz p1, :cond_1

    .line 61
    .line 62
    const/4 v7, 0x0

    .line 63
    iget-object v1, p0, Lr30/c;->e:Ljava/util/List;

    .line 64
    .line 65
    iget-object v2, p0, Lr30/c;->f:Lq30/g;

    .line 66
    .line 67
    iget-object v3, p0, Lr30/c;->g:Lay0/k;

    .line 68
    .line 69
    iget-object v4, p0, Lr30/c;->h:Lay0/a;

    .line 70
    .line 71
    iget-object v5, p0, Lr30/c;->i:Le1/n1;

    .line 72
    .line 73
    invoke-static/range {v1 .. v7}, Lr30/h;->d(Ljava/util/List;Lq30/g;Lay0/k;Lay0/a;Le1/n1;Ll2/o;I)V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_1
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 78
    .line 79
    .line 80
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 81
    .line 82
    return-object p0

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
