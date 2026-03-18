.class public final synthetic Leh/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Ll2/b1;

.field public final synthetic e:Lyj/b;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Lxh/e;

.field public final synthetic h:Lzb/s0;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Lyj/b;Ljava/lang/String;Lxh/e;Lzb/s0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Leh/h;->d:Ll2/b1;

    .line 5
    .line 6
    iput-object p2, p0, Leh/h;->e:Lyj/b;

    .line 7
    .line 8
    iput-object p3, p0, Leh/h;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Leh/h;->g:Lxh/e;

    .line 11
    .line 12
    iput-object p5, p0, Leh/h;->h:Lzb/s0;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Lb1/n;

    .line 2
    .line 3
    check-cast p2, Lz9/k;

    .line 4
    .line 5
    check-cast p3, Ll2/o;

    .line 6
    .line 7
    check-cast p4, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    const-string p4, "$this$composable"

    .line 13
    .line 14
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string p1, "it"

    .line 18
    .line 19
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object p1, p0, Leh/h;->d:Ll2/b1;

    .line 23
    .line 24
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    check-cast p1, Ljava/lang/String;

    .line 29
    .line 30
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    const/4 p4, 0x0

    .line 33
    const/4 v0, 0x0

    .line 34
    check-cast p3, Ll2/t;

    .line 35
    .line 36
    if-nez p1, :cond_0

    .line 37
    .line 38
    const p1, 0x73ccc9f6

    .line 39
    .line 40
    .line 41
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 45
    .line 46
    .line 47
    goto :goto_3

    .line 48
    :cond_0
    const v1, 0x73ccc9f7

    .line 49
    .line 50
    .line 51
    invoke-virtual {p3, v1}, Ll2/t;->Y(I)V

    .line 52
    .line 53
    .line 54
    iget-object v1, p0, Leh/h;->f:Ljava/lang/String;

    .line 55
    .line 56
    if-eqz v1, :cond_1

    .line 57
    .line 58
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-lez v2, :cond_1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    move-object v1, p4

    .line 66
    :goto_0
    iget-object v2, p0, Leh/h;->g:Lxh/e;

    .line 67
    .line 68
    iget-object v3, p0, Leh/h;->h:Lzb/s0;

    .line 69
    .line 70
    if-nez v1, :cond_2

    .line 71
    .line 72
    const v1, -0x6547c098

    .line 73
    .line 74
    .line 75
    invoke-virtual {p3, v1}, Ll2/t;->Y(I)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_2
    const p4, -0x6547c097

    .line 83
    .line 84
    .line 85
    invoke-virtual {p3, p4}, Ll2/t;->Y(I)V

    .line 86
    .line 87
    .line 88
    invoke-static {p1, v2, v3, p3, v0}, Llp/ka;->c(Ljava/lang/String;Lxh/e;Lzb/s0;Ll2/o;I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 92
    .line 93
    .line 94
    move-object p4, p2

    .line 95
    :goto_1
    if-nez p4, :cond_3

    .line 96
    .line 97
    const p4, -0x76e139e1

    .line 98
    .line 99
    .line 100
    invoke-virtual {p3, p4}, Ll2/t;->Y(I)V

    .line 101
    .line 102
    .line 103
    invoke-static {p1, v2, v3, p3, v0}, Llp/x0;->a(Ljava/lang/String;Lxh/e;Lzb/s0;Ll2/o;I)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 107
    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_3
    const p1, -0x76e152f2    # -1.9099928E-33f

    .line 111
    .line 112
    .line 113
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 117
    .line 118
    .line 119
    :goto_2
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 120
    .line 121
    .line 122
    move-object p4, p2

    .line 123
    :goto_3
    if-nez p4, :cond_4

    .line 124
    .line 125
    iget-object p0, p0, Leh/h;->e:Lyj/b;

    .line 126
    .line 127
    invoke-virtual {p0}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    :cond_4
    return-object p2
.end method
