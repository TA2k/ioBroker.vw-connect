.class public final synthetic Ljp/wg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgt/b;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lrn/p;


# direct methods
.method public synthetic constructor <init>(Lrn/p;I)V
    .locals 0

    .line 1
    iput p2, p0, Ljp/wg;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Ljp/wg;->b:Lrn/p;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Ljp/wg;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lon/c;

    .line 7
    .line 8
    const-string v1, "proto"

    .line 9
    .line 10
    invoke-direct {v0, v1}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance v1, Llp/og;

    .line 14
    .line 15
    const/4 v2, 0x2

    .line 16
    invoke-direct {v1, v2}, Llp/og;-><init>(I)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Ljp/wg;->b:Lrn/p;

    .line 20
    .line 21
    const-string v2, "FIREBASE_ML_SDK"

    .line 22
    .line 23
    invoke-virtual {p0, v2, v0, v1}, Lrn/p;->a(Ljava/lang/String;Lon/c;Lon/e;)Lrn/q;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :pswitch_0
    new-instance v0, Lon/c;

    .line 29
    .line 30
    const-string v1, "json"

    .line 31
    .line 32
    invoke-direct {v0, v1}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    new-instance v1, Llp/og;

    .line 36
    .line 37
    const/4 v2, 0x3

    .line 38
    invoke-direct {v1, v2}, Llp/og;-><init>(I)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Ljp/wg;->b:Lrn/p;

    .line 42
    .line 43
    const-string v2, "FIREBASE_ML_SDK"

    .line 44
    .line 45
    invoke-virtual {p0, v2, v0, v1}, Lrn/p;->a(Ljava/lang/String;Lon/c;Lon/e;)Lrn/q;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0

    .line 50
    :pswitch_1
    new-instance v0, Lon/c;

    .line 51
    .line 52
    const-string v1, "proto"

    .line 53
    .line 54
    invoke-direct {v0, v1}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    sget-object v1, Lkp/pa;->g:Lkp/pa;

    .line 58
    .line 59
    iget-object p0, p0, Ljp/wg;->b:Lrn/p;

    .line 60
    .line 61
    const-string v2, "FIREBASE_ML_SDK"

    .line 62
    .line 63
    invoke-virtual {p0, v2, v0, v1}, Lrn/p;->a(Ljava/lang/String;Lon/c;Lon/e;)Lrn/q;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :pswitch_2
    new-instance v0, Lon/c;

    .line 69
    .line 70
    const-string v1, "json"

    .line 71
    .line 72
    invoke-direct {v0, v1}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    sget-object v1, Lkp/pa;->h:Lkp/pa;

    .line 76
    .line 77
    iget-object p0, p0, Ljp/wg;->b:Lrn/p;

    .line 78
    .line 79
    const-string v2, "FIREBASE_ML_SDK"

    .line 80
    .line 81
    invoke-virtual {p0, v2, v0, v1}, Lrn/p;->a(Ljava/lang/String;Lon/c;Lon/e;)Lrn/q;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0

    .line 86
    :pswitch_3
    new-instance v0, Lon/c;

    .line 87
    .line 88
    const-string v1, "proto"

    .line 89
    .line 90
    invoke-direct {v0, v1}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    new-instance v1, Ljp/zg;

    .line 94
    .line 95
    const/4 v2, 0x2

    .line 96
    invoke-direct {v1, v2}, Ljp/zg;-><init>(I)V

    .line 97
    .line 98
    .line 99
    iget-object p0, p0, Ljp/wg;->b:Lrn/p;

    .line 100
    .line 101
    const-string v2, "FIREBASE_ML_SDK"

    .line 102
    .line 103
    invoke-virtual {p0, v2, v0, v1}, Lrn/p;->a(Ljava/lang/String;Lon/c;Lon/e;)Lrn/q;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    :pswitch_4
    new-instance v0, Lon/c;

    .line 109
    .line 110
    const-string v1, "json"

    .line 111
    .line 112
    invoke-direct {v0, v1}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    new-instance v1, Ljp/zg;

    .line 116
    .line 117
    const/4 v2, 0x3

    .line 118
    invoke-direct {v1, v2}, Ljp/zg;-><init>(I)V

    .line 119
    .line 120
    .line 121
    iget-object p0, p0, Ljp/wg;->b:Lrn/p;

    .line 122
    .line 123
    const-string v2, "FIREBASE_ML_SDK"

    .line 124
    .line 125
    invoke-virtual {p0, v2, v0, v1}, Lrn/p;->a(Ljava/lang/String;Lon/c;Lon/e;)Lrn/q;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0

    .line 130
    nop

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
