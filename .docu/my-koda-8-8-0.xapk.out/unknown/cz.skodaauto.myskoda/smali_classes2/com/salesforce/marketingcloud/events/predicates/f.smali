.class public abstract Lcom/salesforce/marketingcloud/events/predicates/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lcom/salesforce/marketingcloud/events/predicates/f;

.field public static final c:Lcom/salesforce/marketingcloud/events/predicates/f;

.field private static final d:Ljava/lang/String;


# instance fields
.field private a:Ljava/lang/Boolean;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/events/predicates/f$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/events/predicates/f$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/events/predicates/f;->b:Lcom/salesforce/marketingcloud/events/predicates/f;

    .line 7
    .line 8
    new-instance v0, Lcom/salesforce/marketingcloud/events/predicates/f$b;

    .line 9
    .line 10
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/events/predicates/f$b;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lcom/salesforce/marketingcloud/events/predicates/f;->c:Lcom/salesforce/marketingcloud/events/predicates/f;

    .line 14
    .line 15
    const-string v0, "Predicate"

    .line 16
    .line 17
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lcom/salesforce/marketingcloud/events/predicates/f;->d:Ljava/lang/String;

    .line 22
    .line 23
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public abstract a()Z
.end method

.method public final b()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/predicates/f;->a:Ljava/lang/Boolean;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/events/predicates/f;->a()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iput-object v0, p0, Lcom/salesforce/marketingcloud/events/predicates/f;->a:Ljava/lang/Boolean;

    .line 14
    .line 15
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/events/predicates/f;->d:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/events/predicates/f;->c()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    iget-object v2, p0, Lcom/salesforce/marketingcloud/events/predicates/f;->a:Ljava/lang/Boolean;

    .line 22
    .line 23
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    const-string v2, "passed"

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    const-string v2, "failed"

    .line 33
    .line 34
    :goto_0
    filled-new-array {v1, v2}, [Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    const-string v2, "%s %s"

    .line 39
    .line 40
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/predicates/f;->a:Ljava/lang/Boolean;

    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    return p0
.end method

.method public abstract c()Ljava/lang/String;
.end method
