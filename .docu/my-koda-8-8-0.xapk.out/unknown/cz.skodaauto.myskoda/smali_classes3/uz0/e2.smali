.class public final Luz0/e2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final b:Luz0/e2;


# instance fields
.field public final synthetic a:Luz0/y;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Luz0/e2;

    .line 2
    .line 3
    invoke-direct {v0}, Luz0/e2;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luz0/e2;->b:Luz0/e2;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Luz0/y;

    .line 5
    .line 6
    const-string v1, "kotlin.Unit"

    .line 7
    .line 8
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    invoke-direct {v0, v2, v1}, Luz0/y;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Luz0/e2;->a:Luz0/y;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/e2;->a:Luz0/y;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Luz0/y;->deserialize(Ltz0/c;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/e2;->a:Luz0/y;

    .line 2
    .line 3
    invoke-virtual {p0}, Luz0/y;->getDescriptor()Lsz0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p2, Llx0/b0;

    .line 2
    .line 3
    const-string v0, "value"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Luz0/e2;->a:Luz0/y;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Luz0/y;->serialize(Ltz0/d;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method
