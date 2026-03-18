.class public final Lmy0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lmy0/b;
.implements Lmy0/m;


# static fields
.field public static final e:Lmy0/a;

.field public static final f:Lmy0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lmy0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lmy0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lmy0/a;->e:Lmy0/a;

    .line 8
    .line 9
    new-instance v0, Lmy0/a;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lmy0/a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lmy0/a;->f:Lmy0/a;

    .line 16
    .line 17
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lmy0/a;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a()Lmy0/l;
    .locals 2

    .line 1
    invoke-static {}, Lmy0/j;->b()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    new-instance p0, Lmy0/l;

    .line 6
    .line 7
    invoke-direct {p0, v0, v1}, Lmy0/l;-><init>(J)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public now()Lmy0/f;
    .locals 0

    .line 1
    sget-object p0, Lmy0/g;->a:Lmy0/b;

    .line 2
    .line 3
    invoke-interface {p0}, Lmy0/b;->now()Lmy0/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lmy0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    sget p0, Lmy0/j;->e:I

    .line 12
    .line 13
    const-string p0, "TimeSource(System.nanoTime())"

    .line 14
    .line 15
    return-object p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
