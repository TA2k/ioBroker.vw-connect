.class public final Lxv/r;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lg4/g;

.field public final synthetic h:Lxv/o;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lg4/g;Lxv/o;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lxv/r;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lxv/r;->g:Lg4/g;

    .line 4
    .line 5
    iput-object p2, p0, Lxv/r;->h:Lxv/o;

    .line 6
    .line 7
    iput-object p3, p0, Lxv/r;->i:Ljava/lang/Object;

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lxv/r;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iget-object v0, p0, Lxv/r;->h:Lxv/o;

    .line 13
    .line 14
    iget-object v0, v0, Lxv/o;->b:Ljava/util/Map;

    .line 15
    .line 16
    iget-object v1, p0, Lxv/r;->g:Lg4/g;

    .line 17
    .line 18
    invoke-static {v1, v0, p1}, Llp/ff;->b(Lg4/g;Ljava/util/Map;I)Lky0/g;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-static {p1}, Lky0/l;->g(Lky0/g;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    check-cast p1, Lxv/i;

    .line 27
    .line 28
    if-eqz p1, :cond_1

    .line 29
    .line 30
    iget-object p1, p1, Lxv/i;->d:Ljava/lang/String;

    .line 31
    .line 32
    iget-object p0, p0, Lxv/r;->i:Ljava/lang/Object;

    .line 33
    .line 34
    instance-of v0, p0, Lxf0/b2;

    .line 35
    .line 36
    if-eqz v0, :cond_0

    .line 37
    .line 38
    check-cast p0, Lxf0/b2;

    .line 39
    .line 40
    iget-object p0, p0, Lxf0/b2;->d:Lay0/k;

    .line 41
    .line 42
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    instance-of v0, p0, Lw3/r0;

    .line 47
    .line 48
    if-eqz v0, :cond_1

    .line 49
    .line 50
    check-cast p0, Lw3/r0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lw3/r0;->a(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    :cond_1
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 59
    .line 60
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 61
    .line 62
    .line 63
    move-result p1

    .line 64
    iget-object v0, p0, Lxv/r;->h:Lxv/o;

    .line 65
    .line 66
    iget-object v0, v0, Lxv/o;->b:Ljava/util/Map;

    .line 67
    .line 68
    iget-object v1, p0, Lxv/r;->g:Lg4/g;

    .line 69
    .line 70
    invoke-static {v1, v0, p1}, Llp/ff;->b(Lg4/g;Ljava/util/Map;I)Lky0/g;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    invoke-static {p1}, Lky0/l;->g(Lky0/g;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    check-cast p1, Lxv/i;

    .line 79
    .line 80
    if-eqz p1, :cond_3

    .line 81
    .line 82
    iget-object p1, p1, Lxv/i;->d:Ljava/lang/String;

    .line 83
    .line 84
    iget-object p0, p0, Lxv/r;->i:Ljava/lang/Object;

    .line 85
    .line 86
    instance-of v0, p0, Lxf0/b2;

    .line 87
    .line 88
    if-eqz v0, :cond_2

    .line 89
    .line 90
    check-cast p0, Lxf0/b2;

    .line 91
    .line 92
    iget-object p0, p0, Lxf0/b2;->d:Lay0/k;

    .line 93
    .line 94
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    goto :goto_1

    .line 98
    :cond_2
    instance-of v0, p0, Lw3/r0;

    .line 99
    .line 100
    if-eqz v0, :cond_3

    .line 101
    .line 102
    check-cast p0, Lw3/r0;

    .line 103
    .line 104
    invoke-virtual {p0, p1}, Lw3/r0;->a(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    return-object p0

    .line 110
    nop

    .line 111
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
