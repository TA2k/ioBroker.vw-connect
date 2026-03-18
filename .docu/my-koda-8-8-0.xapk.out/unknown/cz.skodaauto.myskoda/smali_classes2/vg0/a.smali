.class public final Lvg0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkj0/b;


# static fields
.field public static final b:Lvg0/a;

.field public static final c:Lvg0/a;

.field public static final d:Lvg0/a;

.field public static final e:Lvg0/a;


# instance fields
.field public final synthetic a:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lvg0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lvg0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lvg0/a;->b:Lvg0/a;

    .line 8
    .line 9
    new-instance v0, Lvg0/a;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lvg0/a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lvg0/a;->c:Lvg0/a;

    .line 16
    .line 17
    new-instance v0, Lvg0/a;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lvg0/a;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lvg0/a;->d:Lvg0/a;

    .line 24
    .line 25
    new-instance v0, Lvg0/a;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    invoke-direct {v0, v1}, Lvg0/a;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lvg0/a;->e:Lvg0/a;

    .line 32
    .line 33
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lvg0/a;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lvg0/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "enrollment_start_add_car"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "enrollment_success_add_car"

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    const-string p0, "enrollment_start_activate_car"

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    const-string p0, "enrollment_success_activate_car"

    .line 16
    .line 17
    return-object p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final getParams()Ljava/util/Set;
    .locals 0

    .line 1
    iget p0, p0, Lvg0/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lmx0/u;->d:Lmx0/u;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    sget-object p0, Lmx0/u;->d:Lmx0/u;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    sget-object p0, Lmx0/u;->d:Lmx0/u;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    sget-object p0, Lmx0/u;->d:Lmx0/u;

    .line 16
    .line 17
    return-object p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
