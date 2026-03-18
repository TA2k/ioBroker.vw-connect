.class public final Le2/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le2/i;


# static fields
.field public static final b:Le2/t;

.field public static final c:Le2/t;

.field public static final d:Lc1/y;

.field public static final e:Lc1/y;

.field public static final f:Lc1/y;

.field public static final g:Lc1/y;


# instance fields
.field public final synthetic a:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Le2/t;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Le2/t;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Le2/t;->b:Le2/t;

    .line 8
    .line 9
    new-instance v0, Le2/t;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Le2/t;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Le2/t;->c:Le2/t;

    .line 16
    .line 17
    new-instance v0, Lc1/y;

    .line 18
    .line 19
    const/16 v1, 0x16

    .line 20
    .line 21
    invoke-direct {v0, v1}, Lc1/y;-><init>(I)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Le2/t;->d:Lc1/y;

    .line 25
    .line 26
    new-instance v0, Lc1/y;

    .line 27
    .line 28
    const/16 v1, 0x17

    .line 29
    .line 30
    invoke-direct {v0, v1}, Lc1/y;-><init>(I)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Le2/t;->e:Lc1/y;

    .line 34
    .line 35
    new-instance v0, Lc1/y;

    .line 36
    .line 37
    const/16 v1, 0x18

    .line 38
    .line 39
    invoke-direct {v0, v1}, Lc1/y;-><init>(I)V

    .line 40
    .line 41
    .line 42
    sput-object v0, Le2/t;->f:Lc1/y;

    .line 43
    .line 44
    new-instance v0, Lc1/y;

    .line 45
    .line 46
    const/16 v1, 0x19

    .line 47
    .line 48
    invoke-direct {v0, v1}, Lc1/y;-><init>(I)V

    .line 49
    .line 50
    .line 51
    sput-object v0, Le2/t;->g:Lc1/y;

    .line 52
    .line 53
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Le2/t;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a(Landroidx/collection/h;I)J
    .locals 0

    .line 1
    iget p0, p0, Le2/t;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p1, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lg4/l0;

    .line 9
    .line 10
    invoke-virtual {p0, p2}, Lg4/l0;->j(I)J

    .line 11
    .line 12
    .line 13
    move-result-wide p0

    .line 14
    return-wide p0

    .line 15
    :pswitch_0
    iget-object p0, p1, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lg4/l0;

    .line 18
    .line 19
    iget-object p0, p0, Lg4/l0;->a:Lg4/k0;

    .line 20
    .line 21
    iget-object p0, p0, Lg4/k0;->a:Lg4/g;

    .line 22
    .line 23
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {p2, p0}, Lt1/l0;->s(ILjava/lang/CharSequence;)I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    invoke-static {p2, p0}, Lt1/l0;->r(ILjava/lang/CharSequence;)I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    invoke-static {p1, p0}, Lg4/f0;->b(II)J

    .line 34
    .line 35
    .line 36
    move-result-wide p0

    .line 37
    return-wide p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
