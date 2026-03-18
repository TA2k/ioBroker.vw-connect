.class public final Lxv/q;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lg4/g;

.field public final synthetic h:Lxv/o;


# direct methods
.method public synthetic constructor <init>(Lg4/g;Lxv/o;I)V
    .locals 0

    .line 1
    iput p3, p0, Lxv/q;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lxv/q;->g:Lg4/g;

    .line 4
    .line 5
    iput-object p2, p0, Lxv/q;->h:Lxv/o;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lxv/q;->f:I

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
    iget-object v0, p0, Lxv/q;->h:Lxv/o;

    .line 13
    .line 14
    iget-object v0, v0, Lxv/o;->b:Ljava/util/Map;

    .line 15
    .line 16
    iget-object p0, p0, Lxv/q;->g:Lg4/g;

    .line 17
    .line 18
    invoke-static {p0, v0, p1}, Llp/ff;->b(Lg4/g;Ljava/util/Map;I)Lky0/g;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    iget-object p1, p0, Lky0/g;->a:Lky0/j;

    .line 23
    .line 24
    invoke-interface {p1}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    iget-object v1, p0, Lky0/g;->c:Lay0/k;

    .line 39
    .line 40
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    check-cast v0, Ljava/lang/Boolean;

    .line 45
    .line 46
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    iget-boolean v1, p0, Lky0/g;->b:Z

    .line 51
    .line 52
    if-ne v0, v1, :cond_0

    .line 53
    .line 54
    const/4 p0, 0x1

    .line 55
    goto :goto_0

    .line 56
    :cond_1
    const/4 p0, 0x0

    .line 57
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    iget-object v0, p0, Lxv/q;->h:Lxv/o;

    .line 69
    .line 70
    iget-object v0, v0, Lxv/o;->b:Ljava/util/Map;

    .line 71
    .line 72
    iget-object p0, p0, Lxv/q;->g:Lg4/g;

    .line 73
    .line 74
    invoke-static {p0, v0, p1}, Llp/ff;->b(Lg4/g;Ljava/util/Map;I)Lky0/g;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    iget-object p1, p0, Lky0/g;->a:Lky0/j;

    .line 79
    .line 80
    invoke-interface {p1}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    :cond_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    if-eqz v0, :cond_3

    .line 89
    .line 90
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    iget-object v1, p0, Lky0/g;->c:Lay0/k;

    .line 95
    .line 96
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    check-cast v0, Ljava/lang/Boolean;

    .line 101
    .line 102
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    iget-boolean v1, p0, Lky0/g;->b:Z

    .line 107
    .line 108
    if-ne v0, v1, :cond_2

    .line 109
    .line 110
    const/4 p0, 0x1

    .line 111
    goto :goto_1

    .line 112
    :cond_3
    const/4 p0, 0x0

    .line 113
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    return-object p0

    .line 118
    nop

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
