.class public final synthetic Lb/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lb/h0;


# direct methods
.method public synthetic constructor <init>(Lb/h0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb/b0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lb/b0;->e:Lb/h0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lb/b0;->d:I

    .line 2
    .line 3
    check-cast p1, Lb/c;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "backEvent"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lb/b0;->e:Lb/h0;

    .line 14
    .line 15
    iget-object v0, p0, Lb/h0;->c:Lb/a0;

    .line 16
    .line 17
    if-nez v0, :cond_2

    .line 18
    .line 19
    iget-object p0, p0, Lb/h0;->b:Lmx0/l;

    .line 20
    .line 21
    invoke-virtual {p0}, Lmx0/l;->c()I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    invoke-virtual {p0, v0}, Ljava/util/AbstractList;->listIterator(I)Ljava/util/ListIterator;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    :cond_0
    invoke-interface {p0}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    invoke-interface {p0}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    move-object v1, v0

    .line 40
    check-cast v1, Lb/a0;

    .line 41
    .line 42
    invoke-virtual {v1}, Lb/a0;->isEnabled()Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    const/4 v0, 0x0

    .line 50
    :goto_0
    check-cast v0, Lb/a0;

    .line 51
    .line 52
    :cond_2
    if-eqz v0, :cond_3

    .line 53
    .line 54
    invoke-virtual {v0, p1}, Lb/a0;->handleOnBackProgressed(Lb/c;)V

    .line 55
    .line 56
    .line 57
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_0
    const-string v0, "backEvent"

    .line 61
    .line 62
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget-object p0, p0, Lb/b0;->e:Lb/h0;

    .line 66
    .line 67
    iget-object v0, p0, Lb/h0;->b:Lmx0/l;

    .line 68
    .line 69
    invoke-virtual {v0}, Lmx0/l;->c()I

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    invoke-virtual {v0, v1}, Ljava/util/AbstractList;->listIterator(I)Ljava/util/ListIterator;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    :cond_4
    invoke-interface {v0}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-eqz v1, :cond_5

    .line 82
    .line 83
    invoke-interface {v0}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    move-object v2, v1

    .line 88
    check-cast v2, Lb/a0;

    .line 89
    .line 90
    invoke-virtual {v2}, Lb/a0;->isEnabled()Z

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    if-eqz v2, :cond_4

    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_5
    const/4 v1, 0x0

    .line 98
    :goto_1
    check-cast v1, Lb/a0;

    .line 99
    .line 100
    iget-object v0, p0, Lb/h0;->c:Lb/a0;

    .line 101
    .line 102
    if-eqz v0, :cond_6

    .line 103
    .line 104
    invoke-virtual {p0}, Lb/h0;->b()V

    .line 105
    .line 106
    .line 107
    :cond_6
    iput-object v1, p0, Lb/h0;->c:Lb/a0;

    .line 108
    .line 109
    if-eqz v1, :cond_7

    .line 110
    .line 111
    invoke-virtual {v1, p1}, Lb/a0;->handleOnBackStarted(Lb/c;)V

    .line 112
    .line 113
    .line 114
    :cond_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    return-object p0

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
