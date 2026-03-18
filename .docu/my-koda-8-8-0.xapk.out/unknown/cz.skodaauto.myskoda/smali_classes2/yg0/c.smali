.class public final synthetic Lyg0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lql0/g;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lql0/g;Lay0/k;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lyg0/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lyg0/c;->e:Lql0/g;

    iput-object p2, p0, Lyg0/c;->f:Lay0/k;

    iput-object p3, p0, Lyg0/c;->g:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lql0/g;Lay0/k;Lay0/k;I)V
    .locals 0

    .line 2
    const/4 p4, 0x1

    iput p4, p0, Lyg0/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lyg0/c;->e:Lql0/g;

    iput-object p2, p0, Lyg0/c;->f:Lay0/k;

    iput-object p3, p0, Lyg0/c;->g:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lyg0/c;->d:I

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
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object v0, p0, Lyg0/c;->e:Lql0/g;

    .line 19
    .line 20
    iget-object v1, p0, Lyg0/c;->f:Lay0/k;

    .line 21
    .line 22
    iget-object p0, p0, Lyg0/c;->g:Lay0/k;

    .line 23
    .line 24
    invoke-static {v0, v1, p0, p1, p2}, Lyg0/a;->i(Lql0/g;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    and-int/lit8 v0, p2, 0x3

    .line 35
    .line 36
    const/4 v1, 0x2

    .line 37
    const/4 v2, 0x0

    .line 38
    const/4 v3, 0x1

    .line 39
    if-eq v0, v1, :cond_0

    .line 40
    .line 41
    move v0, v3

    .line 42
    goto :goto_0

    .line 43
    :cond_0
    move v0, v2

    .line 44
    :goto_0
    and-int/2addr p2, v3

    .line 45
    check-cast p1, Ll2/t;

    .line 46
    .line 47
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    if-eqz p2, :cond_1

    .line 52
    .line 53
    iget-object p2, p0, Lyg0/c;->e:Lql0/g;

    .line 54
    .line 55
    iget-object v0, p0, Lyg0/c;->f:Lay0/k;

    .line 56
    .line 57
    iget-object p0, p0, Lyg0/c;->g:Lay0/k;

    .line 58
    .line 59
    invoke-static {p2, v0, p0, p1, v2}, Lyg0/a;->i(Lql0/g;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 64
    .line 65
    .line 66
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
