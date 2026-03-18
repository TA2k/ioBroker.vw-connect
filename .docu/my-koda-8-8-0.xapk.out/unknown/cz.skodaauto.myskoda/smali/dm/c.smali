.class public final Ldm/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldm/g;


# instance fields
.field public final synthetic a:I

.field public final b:Lmm/n;

.field public final c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Lmm/n;I)V
    .locals 0

    .line 1
    iput p3, p0, Ldm/c;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Ldm/c;->c:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Ldm/c;->b:Lmm/n;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget p1, p0, Ldm/c;->a:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/4 v1, 0x0

    .line 5
    iget-object v2, p0, Ldm/c;->c:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object p0, p0, Ldm/c;->b:Lmm/n;

    .line 8
    .line 9
    packed-switch p1, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    check-cast v2, Landroid/graphics/drawable/Drawable;

    .line 13
    .line 14
    sget-object p1, Lsm/i;->a:[Landroid/graphics/Bitmap$Config;

    .line 15
    .line 16
    instance-of p1, v2, Landroid/graphics/drawable/VectorDrawable;

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    if-nez p1, :cond_1

    .line 20
    .line 21
    instance-of p1, v2, Lcb/p;

    .line 22
    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move p1, v1

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    :goto_0
    move p1, v0

    .line 29
    :goto_1
    new-instance v3, Ldm/h;

    .line 30
    .line 31
    if-eqz p1, :cond_3

    .line 32
    .line 33
    invoke-static {p0}, Lmm/i;->a(Lmm/n;)Landroid/graphics/Bitmap$Config;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    iget-object v5, p0, Lmm/n;->b:Lnm/h;

    .line 38
    .line 39
    iget-object v6, p0, Lmm/n;->c:Lnm/g;

    .line 40
    .line 41
    iget-object v7, p0, Lmm/n;->d:Lnm/d;

    .line 42
    .line 43
    sget-object v8, Lnm/d;->e:Lnm/d;

    .line 44
    .line 45
    if-ne v7, v8, :cond_2

    .line 46
    .line 47
    move v1, v0

    .line 48
    :cond_2
    invoke-static {v2, v4, v5, v6, v1}, Lsm/b;->a(Landroid/graphics/drawable/Drawable;Landroid/graphics/Bitmap$Config;Lnm/h;Lnm/g;Z)Landroid/graphics/Bitmap;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    iget-object p0, p0, Lmm/n;->a:Landroid/content/Context;

    .line 53
    .line 54
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    new-instance v2, Landroid/graphics/drawable/BitmapDrawable;

    .line 59
    .line 60
    invoke-direct {v2, p0, v0}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V

    .line 61
    .line 62
    .line 63
    :cond_3
    invoke-static {v2}, Lyl/m;->c(Landroid/graphics/drawable/Drawable;)Lyl/j;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    sget-object v0, Lbm/h;->e:Lbm/h;

    .line 68
    .line 69
    invoke-direct {v3, p0, p1, v0}, Ldm/h;-><init>(Lyl/j;ZLbm/h;)V

    .line 70
    .line 71
    .line 72
    return-object v3

    .line 73
    :pswitch_0
    new-instance p1, Ldm/i;

    .line 74
    .line 75
    check-cast v2, Ljava/nio/ByteBuffer;

    .line 76
    .line 77
    new-instance v1, Ldm/d;

    .line 78
    .line 79
    invoke-direct {v1, v2}, Ldm/d;-><init>(Ljava/nio/ByteBuffer;)V

    .line 80
    .line 81
    .line 82
    invoke-static {v1}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    iget-object p0, p0, Lmm/n;->f:Lu01/k;

    .line 87
    .line 88
    new-instance v3, Lbm/f;

    .line 89
    .line 90
    invoke-direct {v3, v2}, Lbm/f;-><init>(Ljava/nio/ByteBuffer;)V

    .line 91
    .line 92
    .line 93
    new-instance v2, Lbm/s;

    .line 94
    .line 95
    invoke-direct {v2, v1, p0, v3}, Lbm/s;-><init>(Lu01/h;Lu01/k;Ljp/ua;)V

    .line 96
    .line 97
    .line 98
    sget-object p0, Lbm/h;->e:Lbm/h;

    .line 99
    .line 100
    invoke-direct {p1, v2, v0, p0}, Ldm/i;-><init>(Lbm/q;Ljava/lang/String;Lbm/h;)V

    .line 101
    .line 102
    .line 103
    return-object p1

    .line 104
    :pswitch_1
    new-instance p1, Lu01/f;

    .line 105
    .line 106
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 107
    .line 108
    .line 109
    check-cast v2, [B

    .line 110
    .line 111
    invoke-virtual {p1, v2}, Lu01/f;->write([B)V

    .line 112
    .line 113
    .line 114
    iget-object p0, p0, Lmm/n;->f:Lu01/k;

    .line 115
    .line 116
    new-instance v1, Lbm/s;

    .line 117
    .line 118
    invoke-direct {v1, p1, p0, v0}, Lbm/s;-><init>(Lu01/h;Lu01/k;Ljp/ua;)V

    .line 119
    .line 120
    .line 121
    sget-object p0, Lbm/h;->e:Lbm/h;

    .line 122
    .line 123
    new-instance p1, Ldm/i;

    .line 124
    .line 125
    invoke-direct {p1, v1, v0, p0}, Ldm/i;-><init>(Lbm/q;Ljava/lang/String;Lbm/h;)V

    .line 126
    .line 127
    .line 128
    return-object p1

    .line 129
    :pswitch_2
    new-instance p1, Ldm/h;

    .line 130
    .line 131
    check-cast v2, Landroid/graphics/Bitmap;

    .line 132
    .line 133
    iget-object p0, p0, Lmm/n;->a:Landroid/content/Context;

    .line 134
    .line 135
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    new-instance v0, Landroid/graphics/drawable/BitmapDrawable;

    .line 140
    .line 141
    invoke-direct {v0, p0, v2}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V

    .line 142
    .line 143
    .line 144
    invoke-static {v0}, Lyl/m;->c(Landroid/graphics/drawable/Drawable;)Lyl/j;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    sget-object v0, Lbm/h;->e:Lbm/h;

    .line 149
    .line 150
    invoke-direct {p1, p0, v1, v0}, Ldm/h;-><init>(Lyl/j;ZLbm/h;)V

    .line 151
    .line 152
    .line 153
    return-object p1

    .line 154
    nop

    .line 155
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
