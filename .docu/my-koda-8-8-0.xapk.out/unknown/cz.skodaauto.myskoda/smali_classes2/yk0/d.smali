.class public final Lyk0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxj0/f;


# direct methods
.method public synthetic constructor <init>(Lxj0/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Lyk0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyk0/d;->e:Lxj0/f;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 1

    .line 1
    iget v0, p0, Lyk0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lbl0/g0;

    .line 7
    .line 8
    invoke-interface {p1}, Lbl0/g0;->getLocation()Lxj0/f;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iget-object p0, p0, Lyk0/d;->e:Lxj0/f;

    .line 13
    .line 14
    invoke-static {p0, p1}, Llp/pe;->a(Lxj0/f;Lxj0/f;)I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p2, Lbl0/g0;

    .line 23
    .line 24
    invoke-interface {p2}, Lbl0/g0;->getLocation()Lxj0/f;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    invoke-static {p0, p2}, Llp/pe;->a(Lxj0/f;Lxj0/f;)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {p1, p0}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0

    .line 41
    :pswitch_0
    check-cast p1, Lbl0/w;

    .line 42
    .line 43
    iget-object p1, p1, Lbl0/w;->b:Lxj0/f;

    .line 44
    .line 45
    iget-object p0, p0, Lyk0/d;->e:Lxj0/f;

    .line 46
    .line 47
    invoke-static {p0, p1}, Llp/pe;->a(Lxj0/f;Lxj0/f;)I

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    check-cast p2, Lbl0/w;

    .line 56
    .line 57
    iget-object p2, p2, Lbl0/w;->b:Lxj0/f;

    .line 58
    .line 59
    invoke-static {p0, p2}, Llp/pe;->a(Lxj0/f;Lxj0/f;)I

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-static {p1, p0}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    return p0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
