.class public final synthetic Ll30/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(FLmc/t;Lay0/k;I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Ll30/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ll30/b;->e:F

    iput-object p2, p0, Ll30/b;->g:Ljava/lang/Object;

    iput-object p3, p0, Ll30/b;->h:Ljava/lang/Object;

    iput p4, p0, Ll30/b;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Li91/c2;ILjava/util/List;FI)V
    .locals 0

    .line 2
    const/4 p5, 0x0

    iput p5, p0, Ll30/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ll30/b;->g:Ljava/lang/Object;

    iput p2, p0, Ll30/b;->f:I

    iput-object p3, p0, Ll30/b;->h:Ljava/lang/Object;

    iput p4, p0, Ll30/b;->e:F

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;FII)V
    .locals 0

    .line 3
    const/4 p4, 0x2

    iput p4, p0, Ll30/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ll30/b;->g:Ljava/lang/Object;

    iput-object p2, p0, Ll30/b;->h:Ljava/lang/Object;

    iput p3, p0, Ll30/b;->e:F

    iput p5, p0, Ll30/b;->f:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Ll30/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ll30/b;->g:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, Ll30/b;->h:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Ljava/lang/String;

    .line 15
    .line 16
    move-object v4, p1

    .line 17
    check-cast v4, Ll2/o;

    .line 18
    .line 19
    check-cast p2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    const/4 p1, 0x7

    .line 25
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    iget v3, p0, Ll30/b;->e:F

    .line 30
    .line 31
    iget v6, p0, Ll30/b;->f:I

    .line 32
    .line 33
    invoke-static/range {v1 .. v6}, Luz/y;->e(Ljava/lang/String;Ljava/lang/String;FLl2/o;II)V

    .line 34
    .line 35
    .line 36
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    iget-object v0, p0, Ll30/b;->g:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Lmc/t;

    .line 42
    .line 43
    iget-object v1, p0, Ll30/b;->h:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v1, Lay0/k;

    .line 46
    .line 47
    check-cast p1, Ll2/o;

    .line 48
    .line 49
    check-cast p2, Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    iget p2, p0, Ll30/b;->f:I

    .line 55
    .line 56
    or-int/lit8 p2, p2, 0x1

    .line 57
    .line 58
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 59
    .line 60
    .line 61
    move-result p2

    .line 62
    iget p0, p0, Ll30/b;->e:F

    .line 63
    .line 64
    invoke-static {p0, v0, v1, p1, p2}, Lmc/d;->c(FLmc/t;Lay0/k;Ll2/o;I)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :pswitch_1
    iget-object v0, p0, Ll30/b;->g:Ljava/lang/Object;

    .line 69
    .line 70
    move-object v1, v0

    .line 71
    check-cast v1, Li91/c2;

    .line 72
    .line 73
    iget-object v0, p0, Ll30/b;->h:Ljava/lang/Object;

    .line 74
    .line 75
    move-object v3, v0

    .line 76
    check-cast v3, Ljava/util/List;

    .line 77
    .line 78
    move-object v5, p1

    .line 79
    check-cast v5, Ll2/o;

    .line 80
    .line 81
    check-cast p2, Ljava/lang/Integer;

    .line 82
    .line 83
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    const/4 p1, 0x1

    .line 87
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 88
    .line 89
    .line 90
    move-result v6

    .line 91
    iget v2, p0, Ll30/b;->f:I

    .line 92
    .line 93
    iget v4, p0, Ll30/b;->e:F

    .line 94
    .line 95
    invoke-static/range {v1 .. v6}, Llp/ne;->a(Li91/c2;ILjava/util/List;FLl2/o;I)V

    .line 96
    .line 97
    .line 98
    goto :goto_0

    .line 99
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
