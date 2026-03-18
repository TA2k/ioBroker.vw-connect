.class public final Luz0/x1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Luz0/x1;

.field public static final b:Luz0/f0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Luz0/x1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luz0/x1;->a:Luz0/x1;

    .line 7
    .line 8
    const-string v0, "kotlin.UInt"

    .line 9
    .line 10
    sget-object v1, Luz0/k0;->a:Luz0/k0;

    .line 11
    .line 12
    invoke-static {v0, v1}, Luz0/b1;->a(Ljava/lang/String;Lqz0/a;)Luz0/f0;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    sput-object v0, Luz0/x1;->b:Luz0/f0;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Luz0/x1;->b:Luz0/f0;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->C(Lsz0/g;)Ltz0/c;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Ltz0/c;->i()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    new-instance p1, Llx0/u;

    .line 12
    .line 13
    invoke-direct {p1, p0}, Llx0/u;-><init>(I)V

    .line 14
    .line 15
    .line 16
    return-object p1
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Luz0/x1;->b:Luz0/f0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Llx0/u;

    .line 2
    .line 3
    iget p0, p2, Llx0/u;->d:I

    .line 4
    .line 5
    sget-object p2, Luz0/x1;->b:Luz0/f0;

    .line 6
    .line 7
    invoke-interface {p1, p2}, Ltz0/d;->j(Lsz0/g;)Ltz0/d;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-interface {p1, p0}, Ltz0/d;->B(I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method
