.class public final synthetic Lcz/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lbz/u;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lbz/u;Lay0/a;Lay0/a;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lcz/n;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcz/n;->e:Lbz/u;

    iput-object p2, p0, Lcz/n;->f:Lay0/a;

    iput-object p3, p0, Lcz/n;->g:Lay0/a;

    iput-object p4, p0, Lcz/n;->h:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lbz/u;Lay0/a;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p5, 0x1

    iput p5, p0, Lcz/n;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcz/n;->e:Lbz/u;

    iput-object p2, p0, Lcz/n;->f:Lay0/a;

    iput-object p3, p0, Lcz/n;->g:Lay0/a;

    iput-object p4, p0, Lcz/n;->h:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lcz/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/o;

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
    move-result v6

    .line 19
    iget-object v1, p0, Lcz/n;->e:Lbz/u;

    .line 20
    .line 21
    iget-object v2, p0, Lcz/n;->f:Lay0/a;

    .line 22
    .line 23
    iget-object v3, p0, Lcz/n;->g:Lay0/a;

    .line 24
    .line 25
    iget-object v4, p0, Lcz/n;->h:Lay0/a;

    .line 26
    .line 27
    invoke-static/range {v1 .. v6}, Lcz/t;->a(Lbz/u;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 28
    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 34
    .line 35
    check-cast p2, Ljava/lang/Integer;

    .line 36
    .line 37
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    and-int/lit8 v0, p2, 0x3

    .line 42
    .line 43
    const/4 v1, 0x2

    .line 44
    const/4 v2, 0x1

    .line 45
    if-eq v0, v1, :cond_0

    .line 46
    .line 47
    move v0, v2

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    const/4 v0, 0x0

    .line 50
    :goto_0
    and-int/2addr p2, v2

    .line 51
    move-object v5, p1

    .line 52
    check-cast v5, Ll2/t;

    .line 53
    .line 54
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 55
    .line 56
    .line 57
    move-result p1

    .line 58
    if-eqz p1, :cond_1

    .line 59
    .line 60
    const/4 v6, 0x0

    .line 61
    iget-object v1, p0, Lcz/n;->e:Lbz/u;

    .line 62
    .line 63
    iget-object v2, p0, Lcz/n;->f:Lay0/a;

    .line 64
    .line 65
    iget-object v3, p0, Lcz/n;->g:Lay0/a;

    .line 66
    .line 67
    iget-object v4, p0, Lcz/n;->h:Lay0/a;

    .line 68
    .line 69
    invoke-static/range {v1 .. v6}, Lcz/t;->a(Lbz/u;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 74
    .line 75
    .line 76
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 77
    .line 78
    return-object p0

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
