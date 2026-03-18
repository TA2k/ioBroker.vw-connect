.class public final Lqz0/d;
.super Luz0/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lhy0/d;

.field public final b:Ljava/util/List;

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lhy0/d;)V
    .locals 2

    const-string v0, "baseClass"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lqz0/d;->a:Lhy0/d;

    .line 3
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    iput-object p1, p0, Lqz0/d;->b:Ljava/util/List;

    .line 4
    sget-object p1, Llx0/j;->e:Llx0/j;

    new-instance v0, Lmc/e;

    const/16 v1, 0x1d

    invoke-direct {v0, p0, v1}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1, v0}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    move-result-object p1

    iput-object p1, p0, Lqz0/d;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lhy0/d;[Ljava/lang/annotation/Annotation;)V
    .locals 1

    const-string v0, "baseClass"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-direct {p0, p1}, Lqz0/d;-><init>(Lhy0/d;)V

    .line 6
    invoke-static {p2}, Lmx0/n;->b([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Lqz0/d;->b:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final c()Lhy0/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lqz0/d;->a:Lhy0/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lqz0/d;->c:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lsz0/g;

    .line 8
    .line 9
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "kotlinx.serialization.PolymorphicSerializer(baseClass: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lqz0/d;->a:Lhy0/d;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const/16 p0, 0x29

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
