.class public final Lu2/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/z1;


# instance fields
.field public d:Lu2/k;

.field public e:Lu2/g;

.field public f:Ljava/lang/String;

.field public g:Ljava/lang/Object;

.field public h:[Ljava/lang/Object;

.field public i:Lu2/f;

.field public final j:Lu2/a;


# direct methods
.method public constructor <init>(Lu2/k;Lu2/g;Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu2/b;->d:Lu2/k;

    .line 5
    .line 6
    iput-object p2, p0, Lu2/b;->e:Lu2/g;

    .line 7
    .line 8
    iput-object p3, p0, Lu2/b;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lu2/b;->g:Ljava/lang/Object;

    .line 11
    .line 12
    iput-object p5, p0, Lu2/b;->h:[Ljava/lang/Object;

    .line 13
    .line 14
    new-instance p1, Lu2/a;

    .line 15
    .line 16
    const/4 p2, 0x0

    .line 17
    invoke-direct {p1, p0, p2}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lu2/b;->j:Lu2/a;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 4

    .line 1
    iget-object v0, p0, Lu2/b;->e:Lu2/g;

    .line 2
    .line 3
    iget-object v1, p0, Lu2/b;->i:Lu2/f;

    .line 4
    .line 5
    if-nez v1, :cond_4

    .line 6
    .line 7
    if-eqz v0, :cond_3

    .line 8
    .line 9
    iget-object v1, p0, Lu2/b;->j:Lu2/a;

    .line 10
    .line 11
    invoke-virtual {v1}, Lu2/a;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    if-eqz v2, :cond_2

    .line 16
    .line 17
    invoke-interface {v0, v2}, Lu2/g;->d(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-nez v3, :cond_2

    .line 22
    .line 23
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    instance-of v0, v2, Lv2/m;

    .line 26
    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    check-cast v2, Lv2/m;

    .line 30
    .line 31
    invoke-interface {v2}, Lv2/m;->l()Ll2/n2;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sget-object v1, Ll2/x0;->f:Ll2/x0;

    .line 36
    .line 37
    if-eq v0, v1, :cond_0

    .line 38
    .line 39
    invoke-interface {v2}, Lv2/m;->l()Ll2/n2;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    sget-object v1, Ll2/x0;->i:Ll2/x0;

    .line 44
    .line 45
    if-eq v0, v1, :cond_0

    .line 46
    .line 47
    invoke-interface {v2}, Lv2/m;->l()Ll2/n2;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sget-object v1, Ll2/x0;->g:Ll2/x0;

    .line 52
    .line 53
    if-eq v0, v1, :cond_0

    .line 54
    .line 55
    const-string v0, "If you use a custom SnapshotMutationPolicy for your MutableState you have to write a custom Saver"

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string v1, "MutableState containing "

    .line 61
    .line 62
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v1, " cannot be saved using the current SaveableStateRegistry. The default implementation only supports types which can be stored inside the Bundle. Please consider implementing a custom Saver for this class and pass it as a stateSaver parameter to rememberSaveable()."

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    goto :goto_0

    .line 82
    :cond_1
    invoke-static {v2}, Lu2/m;->a(Ljava/lang/Object;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    :goto_0
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw p0

    .line 90
    :cond_2
    iget-object v2, p0, Lu2/b;->f:Ljava/lang/String;

    .line 91
    .line 92
    invoke-interface {v0, v2, v1}, Lu2/g;->a(Ljava/lang/String;Lay0/a;)Lu2/f;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    iput-object v0, p0, Lu2/b;->i:Lu2/f;

    .line 97
    .line 98
    :cond_3
    return-void

    .line 99
    :cond_4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 100
    .line 101
    const-string v1, "entry("

    .line 102
    .line 103
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    iget-object p0, p0, Lu2/b;->i:Lu2/f;

    .line 107
    .line 108
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    const-string p0, ") is not null"

    .line 112
    .line 113
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 121
    .line 122
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    throw v0
.end method

.method public final c()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lu2/b;->a()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final e()V
    .locals 0

    .line 1
    iget-object p0, p0, Lu2/b;->i:Lu2/f;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lrn/i;

    .line 6
    .line 7
    invoke-virtual {p0}, Lrn/i;->C()V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final h()V
    .locals 0

    .line 1
    iget-object p0, p0, Lu2/b;->i:Lu2/f;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lrn/i;

    .line 6
    .line 7
    invoke-virtual {p0}, Lrn/i;->C()V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method
