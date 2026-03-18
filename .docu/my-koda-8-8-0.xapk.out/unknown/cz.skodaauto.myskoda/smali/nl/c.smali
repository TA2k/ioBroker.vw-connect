.class public final Lnl/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lnl/g;


# instance fields
.field public final synthetic a:I

.field public final b:Ltl/l;

.field public final c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ltl/l;I)V
    .locals 0

    .line 1
    iput p3, p0, Lnl/c;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lnl/c;->c:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lnl/c;->b:Ltl/l;

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
    .locals 6

    .line 1
    iget p1, p0, Lnl/c;->a:I

    .line 2
    .line 3
    iget-object v0, p0, Lnl/c;->c:Ljava/lang/Object;

    .line 4
    .line 5
    iget-object p0, p0, Lnl/c;->b:Ltl/l;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    packed-switch p1, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    check-cast v0, Landroid/graphics/drawable/Drawable;

    .line 12
    .line 13
    sget-object p1, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    .line 14
    .line 15
    instance-of p1, v0, Landroid/graphics/drawable/VectorDrawable;

    .line 16
    .line 17
    if-nez p1, :cond_0

    .line 18
    .line 19
    instance-of p1, v0, Lcb/p;

    .line 20
    .line 21
    if-eqz p1, :cond_1

    .line 22
    .line 23
    :cond_0
    const/4 v1, 0x1

    .line 24
    :cond_1
    new-instance p1, Lnl/d;

    .line 25
    .line 26
    if-eqz v1, :cond_2

    .line 27
    .line 28
    iget-object v2, p0, Ltl/l;->b:Landroid/graphics/Bitmap$Config;

    .line 29
    .line 30
    iget-object v3, p0, Ltl/l;->d:Lul/g;

    .line 31
    .line 32
    iget-object v4, p0, Ltl/l;->e:Lul/f;

    .line 33
    .line 34
    iget-boolean v5, p0, Ltl/l;->f:Z

    .line 35
    .line 36
    invoke-static {v0, v2, v3, v4, v5}, Llp/cf;->a(Landroid/graphics/drawable/Drawable;Landroid/graphics/Bitmap$Config;Lul/g;Lul/f;Z)Landroid/graphics/Bitmap;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    iget-object p0, p0, Ltl/l;->a:Landroid/content/Context;

    .line 41
    .line 42
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    new-instance v2, Landroid/graphics/drawable/BitmapDrawable;

    .line 47
    .line 48
    invoke-direct {v2, p0, v0}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V

    .line 49
    .line 50
    .line 51
    move-object v0, v2

    .line 52
    :cond_2
    sget-object p0, Lkl/e;->e:Lkl/e;

    .line 53
    .line 54
    invoke-direct {p1, v0, v1, p0}, Lnl/d;-><init>(Landroid/graphics/drawable/Drawable;ZLkl/e;)V

    .line 55
    .line 56
    .line 57
    return-object p1

    .line 58
    :pswitch_0
    check-cast v0, Ljava/nio/ByteBuffer;

    .line 59
    .line 60
    :try_start_0
    new-instance p1, Lu01/f;

    .line 61
    .line 62
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1, v0}, Lu01/f;->write(Ljava/nio/ByteBuffer;)I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 69
    .line 70
    .line 71
    new-instance v0, Lnl/m;

    .line 72
    .line 73
    iget-object p0, p0, Ltl/l;->a:Landroid/content/Context;

    .line 74
    .line 75
    new-instance v2, Lkl/o;

    .line 76
    .line 77
    new-instance v3, Lkl/m;

    .line 78
    .line 79
    invoke-direct {v3, p0, v1}, Lkl/m;-><init>(Landroid/content/Context;I)V

    .line 80
    .line 81
    .line 82
    const/4 p0, 0x0

    .line 83
    invoke-direct {v2, p1, v3, p0}, Lkl/o;-><init>(Lu01/h;Lay0/a;Llp/qd;)V

    .line 84
    .line 85
    .line 86
    sget-object p1, Lkl/e;->e:Lkl/e;

    .line 87
    .line 88
    invoke-direct {v0, v2, p0, p1}, Lnl/m;-><init>(Lkl/l;Ljava/lang/String;Lkl/e;)V

    .line 89
    .line 90
    .line 91
    return-object v0

    .line 92
    :catchall_0
    move-exception p0

    .line 93
    invoke-virtual {v0, v1}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :pswitch_1
    new-instance p1, Lnl/d;

    .line 98
    .line 99
    check-cast v0, Landroid/graphics/Bitmap;

    .line 100
    .line 101
    iget-object p0, p0, Ltl/l;->a:Landroid/content/Context;

    .line 102
    .line 103
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    new-instance v2, Landroid/graphics/drawable/BitmapDrawable;

    .line 108
    .line 109
    invoke-direct {v2, p0, v0}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V

    .line 110
    .line 111
    .line 112
    sget-object p0, Lkl/e;->e:Lkl/e;

    .line 113
    .line 114
    invoke-direct {p1, v2, v1, p0}, Lnl/d;-><init>(Landroid/graphics/drawable/Drawable;ZLkl/e;)V

    .line 115
    .line 116
    .line 117
    return-object p1

    .line 118
    nop

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
