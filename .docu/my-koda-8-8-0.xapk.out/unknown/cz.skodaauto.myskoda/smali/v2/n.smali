.class public final Lv2/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable$ClassLoaderCreator;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lv2/n;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static a(Landroid/os/Parcel;Ljava/lang/ClassLoader;)Lv2/o;
    .locals 4

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const-class p1, Lv2/n;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    :cond_0
    invoke-virtual {p0}, Landroid/os/Parcel;->readInt()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_1

    .line 14
    .line 15
    new-instance p0, Lv2/o;

    .line 16
    .line 17
    invoke-direct {p0}, Lv2/o;-><init>()V

    .line 18
    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_1
    sget-object v1, Lp2/i;->e:Lp2/i;

    .line 22
    .line 23
    invoke-virtual {v1}, Lp2/i;->k()Lp2/f;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    const/4 v2, 0x0

    .line 28
    :goto_0
    if-ge v2, v0, :cond_2

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->readValue(Ljava/lang/ClassLoader;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    invoke-virtual {v1, v3}, Lp2/f;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    add-int/lit8 v2, v2, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    new-instance p0, Lv2/o;

    .line 41
    .line 42
    invoke-virtual {v1}, Lp2/f;->g()Lp2/c;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-direct {p0, p1}, Lv2/o;-><init>(Lp2/c;)V

    .line 47
    .line 48
    .line 49
    return-object p0
.end method


# virtual methods
.method public final createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;
    .locals 1

    iget p0, p0, Lv2/n;->a:I

    packed-switch p0, :pswitch_data_0

    .line 14
    new-instance p0, Lzq/x;

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Lzq/x;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 15
    :pswitch_0
    new-instance p0, Lxq/b;

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Lxq/b;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 16
    :pswitch_1
    new-instance p0, Lrq/a;

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Lrq/a;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 17
    :pswitch_2
    new-instance p0, Lm/u2;

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Lm/u2;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 18
    :pswitch_3
    new-instance p0, Ll5/e;

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Ll5/e;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 19
    :pswitch_4
    new-instance p0, Lka/o0;

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Lka/o0;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 20
    :pswitch_5
    new-instance p0, Ljq/c;

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Ljq/c;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    :pswitch_6
    const/4 p0, 0x0

    .line 21
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    move-result-object p0

    if-nez p0, :cond_0

    .line 22
    sget-object p0, Lj6/b;->e:Lj6/a;

    return-object p0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "superState must be null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 24
    :pswitch_7
    new-instance p0, Liq/d;

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Liq/d;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 25
    :pswitch_8
    new-instance p0, Landroidx/fragment/app/i0;

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Landroidx/fragment/app/i0;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    :pswitch_9
    const/4 p0, 0x0

    .line 26
    invoke-static {p1, p0}, Lv2/n;->a(Landroid/os/Parcel;Ljava/lang/ClassLoader;)Lv2/o;

    move-result-object p0

    return-object p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final createFromParcel(Landroid/os/Parcel;Ljava/lang/ClassLoader;)Ljava/lang/Object;
    .locals 0

    iget p0, p0, Lv2/n;->a:I

    packed-switch p0, :pswitch_data_0

    .line 1
    new-instance p0, Lzq/x;

    invoke-direct {p0, p1, p2}, Lzq/x;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 2
    :pswitch_0
    new-instance p0, Lxq/b;

    invoke-direct {p0, p1, p2}, Lxq/b;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 3
    :pswitch_1
    new-instance p0, Lrq/a;

    invoke-direct {p0, p1, p2}, Lrq/a;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 4
    :pswitch_2
    new-instance p0, Lm/u2;

    invoke-direct {p0, p1, p2}, Lm/u2;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 5
    :pswitch_3
    new-instance p0, Ll5/e;

    invoke-direct {p0, p1, p2}, Ll5/e;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 6
    :pswitch_4
    new-instance p0, Lka/o0;

    invoke-direct {p0, p1, p2}, Lka/o0;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 7
    :pswitch_5
    new-instance p0, Ljq/c;

    invoke-direct {p0, p1, p2}, Ljq/c;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 8
    :pswitch_6
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    move-result-object p0

    if-nez p0, :cond_0

    .line 9
    sget-object p0, Lj6/b;->e:Lj6/a;

    return-object p0

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "superState must be null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 11
    :pswitch_7
    new-instance p0, Liq/d;

    invoke-direct {p0, p1, p2}, Liq/d;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 12
    :pswitch_8
    new-instance p0, Landroidx/fragment/app/i0;

    invoke-direct {p0, p1, p2}, Landroidx/fragment/app/i0;-><init>(Landroid/os/Parcel;Ljava/lang/ClassLoader;)V

    return-object p0

    .line 13
    :pswitch_9
    invoke-static {p1, p2}, Lv2/n;->a(Landroid/os/Parcel;Ljava/lang/ClassLoader;)Lv2/o;

    move-result-object p0

    return-object p0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lv2/n;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-array p0, p1, [Lzq/x;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    new-array p0, p1, [Lxq/b;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    new-array p0, p1, [Lrq/a;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    new-array p0, p1, [Lm/u2;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_3
    new-array p0, p1, [Ll5/e;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_4
    new-array p0, p1, [Lka/o0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_5
    new-array p0, p1, [Ljq/c;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_6
    new-array p0, p1, [Lj6/b;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_7
    new-array p0, p1, [Liq/d;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_8
    new-array p0, p1, [Landroidx/fragment/app/i0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_9
    new-array p0, p1, [Lv2/o;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
