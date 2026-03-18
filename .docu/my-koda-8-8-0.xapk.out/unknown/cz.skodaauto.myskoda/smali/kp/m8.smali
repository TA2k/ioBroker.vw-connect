.class public abstract Lkp/m8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Lhp/m;


# direct methods
.method public static final a(Lx11/a;Lt2/b;Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, -0x7f48b668

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    or-int/lit8 v0, p3, 0x2

    .line 10
    .line 11
    and-int/lit8 v1, v0, 0x13

    .line 12
    .line 13
    const/16 v2, 0x12

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    if-eq v1, v2, :cond_0

    .line 17
    .line 18
    move v1, v3

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v1, 0x0

    .line 21
    :goto_0
    and-int/2addr v0, v3

    .line 22
    invoke-virtual {p2, v0, v1}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_3

    .line 27
    .line 28
    invoke-virtual {p2}, Ll2/t;->T()V

    .line 29
    .line 30
    .line 31
    and-int/lit8 v0, p3, 0x1

    .line 32
    .line 33
    if-eqz v0, :cond_2

    .line 34
    .line 35
    invoke-virtual {p2}, Ll2/t;->y()Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 43
    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    :goto_1
    sget-object p0, Lg31/a;->d:Lg31/a;

    .line 47
    .line 48
    iget-object p0, p0, Lh/w;->b:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, Llx0/q;

    .line 51
    .line 52
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    check-cast p0, Lx11/a;

    .line 57
    .line 58
    :goto_2
    invoke-virtual {p2}, Ll2/t;->r()V

    .line 59
    .line 60
    .line 61
    const/16 v0, 0x30

    .line 62
    .line 63
    invoke-static {p0, p1, p2, v0}, Lw11/c;->a(Lx11/a;Lt2/b;Ll2/o;I)V

    .line 64
    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 68
    .line 69
    .line 70
    :goto_3
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    if-eqz p2, :cond_4

    .line 75
    .line 76
    new-instance v0, Ld90/m;

    .line 77
    .line 78
    const/16 v1, 0x12

    .line 79
    .line 80
    invoke-direct {v0, p3, v1, p0, p1}, Ld90/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 84
    .line 85
    :cond_4
    return-void
.end method

.method public static b(Landroid/graphics/Bitmap;)Lsp/b;
    .locals 3

    .line 1
    const-string v0, "image must not be null"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance v0, Lsp/b;

    .line 7
    .line 8
    sget-object v1, Lkp/m8;->a:Lhp/m;

    .line 9
    .line 10
    const-string v2, "IBitmapDescriptorFactory is not initialized"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    check-cast v1, Lhp/k;

    .line 16
    .line 17
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-static {v2, p0}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 22
    .line 23
    .line 24
    const/4 p0, 0x6

    .line 25
    invoke-virtual {v1, v2, p0}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-static {v1}, Lyo/b;->T(Landroid/os/IBinder;)Lyo/a;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 38
    .line 39
    .line 40
    invoke-direct {v0, v1}, Lsp/b;-><init>(Lyo/a;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 41
    .line 42
    .line 43
    return-object v0

    .line 44
    :catch_0
    move-exception p0

    .line 45
    new-instance v0, La8/r0;

    .line 46
    .line 47
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 48
    .line 49
    .line 50
    throw v0
.end method
