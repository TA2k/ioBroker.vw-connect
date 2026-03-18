.class public final Lmz0/c;
.super Luz0/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lmz0/c;

.field public static final b:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lmz0/c;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lmz0/c;->a:Lmz0/c;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, Lmz0/b;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {v1, v2}, Lmz0/b;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sput-object v0, Lmz0/c;->b:Ljava/lang/Object;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final a(Ltz0/a;Ljava/lang/String;)Lqz0/a;
    .locals 0

    .line 1
    sget-object p0, Lmz0/c;->b:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqz0/f;

    .line 8
    .line 9
    invoke-virtual {p0, p1, p2}, Lqz0/f;->a(Ltz0/a;Ljava/lang/String;)Lqz0/a;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public final b(Ltz0/d;Ljava/lang/Object;)Lqz0/a;
    .locals 0

    .line 1
    check-cast p2, Lgz0/k;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lmz0/c;->b:Ljava/lang/Object;

    .line 9
    .line 10
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lqz0/f;

    .line 15
    .line 16
    invoke-virtual {p0, p1, p2}, Lqz0/f;->b(Ltz0/d;Ljava/lang/Object;)Lqz0/a;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public final c()Lhy0/d;
    .locals 1

    .line 1
    const-class p0, Lgz0/k;

    .line 2
    .line 3
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lmz0/c;->b:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqz0/f;

    .line 8
    .line 9
    invoke-virtual {p0}, Lqz0/f;->getDescriptor()Lsz0/g;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method
