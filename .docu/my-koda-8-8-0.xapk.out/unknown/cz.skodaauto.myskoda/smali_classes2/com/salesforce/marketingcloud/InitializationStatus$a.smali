.class public final Lcom/salesforce/marketingcloud/InitializationStatus$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/InitializationStatus;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# instance fields
.field private a:Ljava/lang/Throwable;

.field private b:Z

.field private c:Z

.field private d:Z

.field private e:Z

.field private f:Z

.field private g:Ljava/lang/String;

.field private h:I

.field private i:Z

.field private final j:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->h:I

    .line 6
    .line 7
    new-instance v0, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->j:Ljava/util/List;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a()Lcom/salesforce/marketingcloud/InitializationStatus;
    .locals 17

    move-object/from16 v0, p0

    .line 16
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->b()Z

    move-result v1

    if-eqz v1, :cond_2

    .line 17
    iget-boolean v1, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->b:Z

    if-nez v1, :cond_1

    iget-boolean v1, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->d:Z

    if-nez v1, :cond_1

    iget-boolean v1, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->e:Z

    if-nez v1, :cond_1

    iget-boolean v1, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->i:Z

    if-nez v1, :cond_1

    iget-boolean v1, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->f:Z

    if-eqz v1, :cond_0

    goto :goto_1

    .line 18
    :cond_0
    sget-object v1, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->SUCCESS:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    :goto_0
    move-object v3, v1

    goto :goto_2

    .line 19
    :cond_1
    :goto_1
    sget-object v1, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->COMPLETED_WITH_DEGRADED_FUNCTIONALITY:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    goto :goto_0

    .line 20
    :cond_2
    sget-object v1, Lcom/salesforce/marketingcloud/InitializationStatus$Status;->FAILED:Lcom/salesforce/marketingcloud/InitializationStatus$Status;

    goto :goto_0

    .line 21
    :goto_2
    new-instance v2, Lcom/salesforce/marketingcloud/InitializationStatus;

    .line 22
    iget-object v4, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a:Ljava/lang/Throwable;

    .line 23
    iget-boolean v5, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->b:Z

    .line 24
    iget v6, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->h:I

    .line 25
    iget-object v7, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->g:Ljava/lang/String;

    .line 26
    iget-boolean v8, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->c:Z

    .line 27
    iget-boolean v9, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->d:Z

    .line 28
    iget-boolean v10, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->i:Z

    .line 29
    iget-boolean v11, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->e:Z

    .line 30
    iget-boolean v12, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->f:Z

    .line 31
    iget-object v0, v0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->j:Ljava/util/List;

    const/4 v1, 0x0

    .line 32
    new-array v1, v1, [Ljava/lang/String;

    invoke-interface {v0, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    .line 33
    check-cast v0, [Ljava/lang/String;

    array-length v1, v0

    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v13

    const/16 v15, 0x800

    const/16 v16, 0x0

    const/4 v14, 0x0

    .line 34
    invoke-direct/range {v2 .. v16}, Lcom/salesforce/marketingcloud/InitializationStatus;-><init>(Lcom/salesforce/marketingcloud/InitializationStatus$Status;Ljava/lang/Throwable;ZILjava/lang/String;ZZZZZLjava/util/List;ZILkotlin/jvm/internal/g;)V

    return-object v2
.end method

.method public final a(I)V
    .locals 0

    .line 2
    iput p1, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->h:I

    return-void
.end method

.method public final a(Lcom/salesforce/marketingcloud/d;)V
    .locals 1

    const-string v0, "component"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    iget-object p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->j:Ljava/util/List;

    invoke-interface {p1}, Lcom/salesforce/marketingcloud/d;->componentName()Ljava/lang/String;

    move-result-object p1

    const-string v0, "componentName(...)"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final a(Ljava/lang/String;)V
    .locals 2

    if-eqz p1, :cond_1

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->g:Ljava/lang/String;

    if-nez v0, :cond_0

    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->g:Ljava/lang/String;

    return-void

    .line 5
    :cond_0
    const-string v1, "\n"

    .line 6
    invoke-static {v0, v1, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 7
    iput-object p1, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->g:Ljava/lang/String;

    :cond_1
    return-void
.end method

.method public final a(Ljava/lang/Throwable;)V
    .locals 1

    const-string v0, "throwable"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a:Ljava/lang/Throwable;

    return-void
.end method

.method public final a(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->c:Z

    return-void
.end method

.method public final b(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->b:Z

    return-void
.end method

.method public final b()Z
    .locals 0

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a:Ljava/lang/Throwable;

    if-nez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public final c(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->e:Z

    .line 2
    .line 3
    return-void
.end method

.method public final d(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->i:Z

    .line 2
    .line 3
    return-void
.end method

.method public final e(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->f:Z

    .line 2
    .line 3
    return-void
.end method

.method public final f(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/InitializationStatus$a;->d:Z

    .line 2
    .line 3
    return-void
.end method
