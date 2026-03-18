.class public final synthetic Ll20/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lk20/o;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lc3/j;


# direct methods
.method public synthetic constructor <init>(Lk20/o;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lc3/j;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ll20/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ll20/h;->e:Lk20/o;

    iput-object p2, p0, Ll20/h;->f:Lay0/a;

    iput-object p3, p0, Ll20/h;->g:Lay0/k;

    iput-object p4, p0, Ll20/h;->h:Lay0/a;

    iput-object p5, p0, Ll20/h;->i:Lay0/a;

    iput-object p6, p0, Ll20/h;->j:Lc3/j;

    return-void
.end method

.method public synthetic constructor <init>(Lk20/o;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lc3/j;I)V
    .locals 0

    .line 2
    const/4 p7, 0x1

    iput p7, p0, Ll20/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ll20/h;->e:Lk20/o;

    iput-object p2, p0, Ll20/h;->f:Lay0/a;

    iput-object p3, p0, Ll20/h;->g:Lay0/k;

    iput-object p4, p0, Ll20/h;->h:Lay0/a;

    iput-object p5, p0, Ll20/h;->i:Lay0/a;

    iput-object p6, p0, Ll20/h;->j:Lc3/j;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Ll20/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v7, p1

    .line 7
    check-cast v7, Ll2/o;

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
    move-result v8

    .line 19
    iget-object v1, p0, Ll20/h;->e:Lk20/o;

    .line 20
    .line 21
    iget-object v2, p0, Ll20/h;->f:Lay0/a;

    .line 22
    .line 23
    iget-object v3, p0, Ll20/h;->g:Lay0/k;

    .line 24
    .line 25
    iget-object v4, p0, Ll20/h;->h:Lay0/a;

    .line 26
    .line 27
    iget-object v5, p0, Ll20/h;->i:Lay0/a;

    .line 28
    .line 29
    iget-object v6, p0, Ll20/h;->j:Lc3/j;

    .line 30
    .line 31
    invoke-static/range {v1 .. v8}, Ll20/a;->s(Lk20/o;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lc3/j;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 38
    .line 39
    check-cast p2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 42
    .line 43
    .line 44
    move-result p2

    .line 45
    and-int/lit8 v0, p2, 0x3

    .line 46
    .line 47
    const/4 v1, 0x2

    .line 48
    const/4 v2, 0x1

    .line 49
    if-eq v0, v1, :cond_0

    .line 50
    .line 51
    move v0, v2

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    const/4 v0, 0x0

    .line 54
    :goto_0
    and-int/2addr p2, v2

    .line 55
    move-object v7, p1

    .line 56
    check-cast v7, Ll2/t;

    .line 57
    .line 58
    invoke-virtual {v7, p2, v0}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    if-eqz p1, :cond_1

    .line 63
    .line 64
    const/4 v8, 0x0

    .line 65
    iget-object v1, p0, Ll20/h;->e:Lk20/o;

    .line 66
    .line 67
    iget-object v2, p0, Ll20/h;->f:Lay0/a;

    .line 68
    .line 69
    iget-object v3, p0, Ll20/h;->g:Lay0/k;

    .line 70
    .line 71
    iget-object v4, p0, Ll20/h;->h:Lay0/a;

    .line 72
    .line 73
    iget-object v5, p0, Ll20/h;->i:Lay0/a;

    .line 74
    .line 75
    iget-object v6, p0, Ll20/h;->j:Lc3/j;

    .line 76
    .line 77
    invoke-static/range {v1 .. v8}, Ll20/a;->s(Lk20/o;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lc3/j;Ll2/o;I)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_1
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 82
    .line 83
    .line 84
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
