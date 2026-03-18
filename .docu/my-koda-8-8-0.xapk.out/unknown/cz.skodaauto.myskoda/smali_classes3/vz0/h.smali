.class public final Lvz0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Lvz0/h;

.field public static final b:Lvz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lvz0/h;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lvz0/h;->a:Lvz0/h;

    .line 7
    .line 8
    sget-object v0, Lvz0/g;->b:Lvz0/g;

    .line 9
    .line 10
    sput-object v0, Lvz0/h;->b:Lvz0/g;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-static {p1}, Llp/qc;->b(Ltz0/c;)Lvz0/l;

    .line 2
    .line 3
    .line 4
    new-instance p0, Lvz0/f;

    .line 5
    .line 6
    sget-object v0, Lvz0/p;->a:Lvz0/p;

    .line 7
    .line 8
    invoke-static {v0}, Lkp/u6;->a(Lqz0/a;)Luz0/d;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {v0, p1}, Luz0/a;->deserialize(Ltz0/c;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    check-cast p1, Ljava/util/List;

    .line 17
    .line 18
    invoke-direct {p0, p1}, Lvz0/f;-><init>(Ljava/util/List;)V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lvz0/h;->b:Lvz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Lvz0/f;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p1}, Llp/qc;->a(Ltz0/d;)V

    .line 9
    .line 10
    .line 11
    sget-object p0, Lvz0/p;->a:Lvz0/p;

    .line 12
    .line 13
    invoke-static {p0}, Lkp/u6;->a(Lqz0/a;)Luz0/d;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0, p1, p2}, Luz0/r;->serialize(Ltz0/d;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
