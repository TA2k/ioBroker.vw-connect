.class public final Le1/h0;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/c2;


# static fields
.field public static final s:Le1/f1;


# instance fields
.field public r:Le81/w;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Le1/f1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Le1/h0;->s:Le1/f1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final X0(Lt3/y;)V
    .locals 1

    .line 1
    iget-object v0, p0, Le1/h0;->r:Le81/w;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Le81/w;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Le1/h0;

    .line 11
    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Le1/h0;->X0(Lt3/y;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final g()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Le1/h0;->s:Le1/f1;

    .line 2
    .line 3
    return-object p0
.end method
