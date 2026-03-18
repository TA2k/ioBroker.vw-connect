.class public final Lcw/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lcw/k;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcw/k;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcw/l;->Companion:Lcw/k;

    .line 7
    .line 8
    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    and-int/lit8 v0, p1, 0x23

    const/4 v1, 0x0

    const/16 v2, 0x23

    if-ne v2, v0, :cond_3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lcw/l;->a:Ljava/lang/String;

    iput-object p3, p0, Lcw/l;->b:Ljava/lang/String;

    and-int/lit8 p2, p1, 0x4

    if-nez p2, :cond_0

    iput-object v1, p0, Lcw/l;->c:Ljava/lang/String;

    goto :goto_0

    :cond_0
    iput-object p4, p0, Lcw/l;->c:Ljava/lang/String;

    :goto_0
    and-int/lit8 p2, p1, 0x8

    if-nez p2, :cond_1

    iput-object v1, p0, Lcw/l;->d:Ljava/lang/String;

    goto :goto_1

    :cond_1
    iput-object p5, p0, Lcw/l;->d:Ljava/lang/String;

    :goto_1
    and-int/lit8 p1, p1, 0x10

    if-nez p1, :cond_2

    iput-object v1, p0, Lcw/l;->e:Ljava/lang/String;

    goto :goto_2

    :cond_2
    iput-object p6, p0, Lcw/l;->e:Ljava/lang/String;

    :goto_2
    iput-object p7, p0, Lcw/l;->f:Ljava/lang/String;

    return-void

    :cond_3
    sget-object p0, Lcw/j;->a:Lcw/j;

    invoke-virtual {p0}, Lcw/j;->getDescriptor()Lsz0/g;

    move-result-object p0

    invoke-static {p1, v2, p0}, Luz0/b1;->l(IILsz0/g;)V

    throw v1
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const-string v0, "hash"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcw/l;->a:Ljava/lang/String;

    .line 4
    iput-object p2, p0, Lcw/l;->b:Ljava/lang/String;

    .line 5
    iput-object p3, p0, Lcw/l;->c:Ljava/lang/String;

    .line 6
    iput-object p4, p0, Lcw/l;->d:Ljava/lang/String;

    .line 7
    iput-object p5, p0, Lcw/l;->e:Ljava/lang/String;

    .line 8
    iput-object p6, p0, Lcw/l;->f:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    const/4 v1, 0x0

    .line 6
    if-eqz p1, :cond_3

    .line 7
    .line 8
    const-class v2, Lcw/l;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    if-eq v2, v3, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    check-cast p1, Lcw/l;

    .line 18
    .line 19
    iget-object p0, p0, Lcw/l;->f:Ljava/lang/String;

    .line 20
    .line 21
    iget-object p1, p1, Lcw/l;->f:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-nez p0, :cond_2

    .line 28
    .line 29
    return v1

    .line 30
    :cond_2
    return v0

    .line 31
    :cond_3
    :goto_0
    return v1
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcw/l;->f:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", url="

    .line 2
    .line 3
    const-string v1, ", year="

    .line 4
    .line 5
    const-string v2, "License(name="

    .line 6
    .line 7
    iget-object v3, p0, Lcw/l;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lcw/l;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", spdxId="

    .line 16
    .line 17
    const-string v2, ", licenseContent="

    .line 18
    .line 19
    iget-object v3, p0, Lcw/l;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lcw/l;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", hash="

    .line 27
    .line 28
    const-string v2, ")"

    .line 29
    .line 30
    iget-object v3, p0, Lcw/l;->e:Ljava/lang/String;

    .line 31
    .line 32
    iget-object p0, p0, Lcw/l;->f:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method
