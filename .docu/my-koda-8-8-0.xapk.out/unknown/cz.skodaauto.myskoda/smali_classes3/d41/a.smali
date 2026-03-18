.class public final synthetic Ld41/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz70/a;

.field public final synthetic f:Lq31/i;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lz70/a;Lq31/i;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ld41/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld41/a;->e:Lz70/a;

    iput-object p2, p0, Ld41/a;->f:Lq31/i;

    iput-object p3, p0, Ld41/a;->g:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lz70/a;Lq31/i;Lay0/k;I)V
    .locals 0

    .line 2
    const/4 p4, 0x1

    iput p4, p0, Ld41/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld41/a;->e:Lz70/a;

    iput-object p2, p0, Ld41/a;->f:Lq31/i;

    iput-object p3, p0, Ld41/a;->g:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Ld41/a;->d:I

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
    const/16 p2, 0x41

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget-object v0, p0, Ld41/a;->e:Lz70/a;

    .line 20
    .line 21
    iget-object v1, p0, Ld41/a;->f:Lq31/i;

    .line 22
    .line 23
    iget-object p0, p0, Ld41/a;->g:Lay0/k;

    .line 24
    .line 25
    invoke-static {v0, v1, p0, p1, p2}, Ljp/nf;->a(Lz70/a;Lq31/i;Lay0/k;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
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
    move-result p2

    .line 35
    and-int/lit8 v0, p2, 0x3

    .line 36
    .line 37
    const/4 v1, 0x2

    .line 38
    const/4 v2, 0x1

    .line 39
    if-eq v0, v1, :cond_0

    .line 40
    .line 41
    move v0, v2

    .line 42
    goto :goto_0

    .line 43
    :cond_0
    const/4 v0, 0x0

    .line 44
    :goto_0
    and-int/2addr p2, v2

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
    const/16 p2, 0x40

    .line 54
    .line 55
    iget-object v0, p0, Ld41/a;->e:Lz70/a;

    .line 56
    .line 57
    iget-object v1, p0, Ld41/a;->f:Lq31/i;

    .line 58
    .line 59
    iget-object p0, p0, Ld41/a;->g:Lay0/k;

    .line 60
    .line 61
    invoke-static {v0, v1, p0, p1, p2}, Ljp/nf;->a(Lz70/a;Lq31/i;Lay0/k;Ll2/o;I)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 66
    .line 67
    .line 68
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    return-object p0

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
